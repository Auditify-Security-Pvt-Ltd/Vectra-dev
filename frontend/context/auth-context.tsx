'use client'

import {
  createContext,
  useContext,
  useEffect,
  useState,
  ReactNode,
} from 'react'
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  sendPasswordResetEmail,
  onAuthStateChanged,
  User as FirebaseUser,
} from 'firebase/auth'
import {
  doc,
  getDoc,
  setDoc,
  updateDoc,
  serverTimestamp,
  writeBatch,
} from 'firebase/firestore'
import { auth, db } from '@/lib/firebase'
import type { OrgRole } from '@/lib/rbac'
import { platformRoleToOrgRole } from '@/lib/rbac'
import { createOrg, addMember, getMember } from '@/lib/firestore-team'
import { registerOrg } from '@/lib/api-team'
import { validateOrganization, type OrganizationInput } from '@/lib/org-validation'

export type UserRole =
  | 'customer'
  | 'analyst'
  | 'team_admin'
  | 'super_admin'
  | 'platform_admin'

export interface AuthUser {
  uid:            string
  email:          string
  name:           string
  role:           UserRole
  orgRole:        OrgRole
  status:         string
  organizationId: string
}

interface AuthContextValue {
  user:          AuthUser | null
  role:          UserRole | null
  orgRole:       OrgRole | null
  loading:       boolean
  login:         (email: string, password: string) => Promise<{ role: UserRole }>
  /**
   * `organization` given → new customer: creates the organization and makes the
   * user its owner. `null` → invited user: creates the account only; the
   * invitation then adds them to the existing organization.
   */
  register:      (name: string, email: string, password: string, organization: OrganizationInput | null) => Promise<void>
  logout:        () => Promise<void>
  resetPassword: (email: string) => Promise<void>
  refreshUser:   () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

async function resolveOrgRole(
  uid: string,
  organizationId: string,
  platformRole: UserRole,
  hasOrganization: boolean,
): Promise<OrgRole> {
  // Owner of their own workspace is always admin. An account that has not joined
  // any organization yet (invite pending) gets no implicit ownership.
  if (!hasOrganization) return 'viewer'
  if (organizationId === uid) return 'admin'
  try {
    const member = await getMember(organizationId, uid)
    if (member) return member.orgRole
  } catch {
    // Firestore read failed — fall back to platform role mapping
  }
  return platformRoleToOrgRole(platformRole)
}

async function fetchUserDoc(firebaseUser: FirebaseUser): Promise<AuthUser | null> {
  try {
    const snap = await getDoc(doc(db, 'users', firebaseUser.uid))
    if (!snap.exists()) return null
    const d = snap.data()
    const orgId   = d.organizationId ?? firebaseUser.uid
    const orgRole = await resolveOrgRole(firebaseUser.uid, orgId, d.role as UserRole, !!d.organizationId)
    return {
      uid:            firebaseUser.uid,
      email:          d.email,
      name:           d.name,
      role:           d.role as UserRole,
      orgRole,
      status:         d.status,
      organizationId: orgId,
    }
  } catch {
    return null
  }
}

/**
 * Repair for legacy accounts whose own-workspace organization document is
 * missing. Runs only when the user record itself says they own a workspace
 * (organizationId === uid), so invited members never get a duplicate org.
 */
async function ensureOrgExists(uid: string, name: string, email: string): Promise<void> {
  try {
    const snap = await getDoc(doc(db, 'users', uid))
    if (!snap.exists() || snap.data().organizationId !== uid) return

    const { getOrg } = await import('@/lib/firestore-team')
    const existing = await getOrg(uid)
    if (existing) return

    const orgName = `${name}'s Workspace`
    await createOrg({ orgId: uid, ownerId: uid, ownerName: name, ownerEmail: email, name: orgName, createdAt: '' as any })
    await addMember(uid, { userId: uid, name, email, orgRole: 'admin', status: 'active', joinedAt: '' as any })
    // Register in backend memory (best-effort — backend restarts clear this, which is acceptable)
    await registerOrg(uid, uid, orgName).catch(() => {})
  } catch {
    // Non-fatal — org creation is a convenience, not a hard requirement
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser]       = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        const appUser = await fetchUserDoc(firebaseUser)
        setUser(appUser)
        if (appUser) {
          // Ensure org exists in the background (idempotent)
          ensureOrgExists(appUser.uid, appUser.name, appUser.email)
        }
      } else {
        setUser(null)
      }
      setLoading(false)
    })
    return unsubscribe
  }, [])

  const refreshUser = async (): Promise<void> => {
    const firebaseUser = auth.currentUser
    if (!firebaseUser) return
    const appUser = await fetchUserDoc(firebaseUser)
    setUser(appUser)
  }

  const login = async (email: string, password: string): Promise<{ role: UserRole }> => {
    const cred = await signInWithEmailAndPassword(auth, email, password)
    const snap = await getDoc(doc(db, 'users', cred.user.uid))

    if (!snap.exists()) {
      await signOut(auth)
      throw new Error('User account not found. Please contact support.')
    }

    const d      = snap.data()
    const orgId  = d.organizationId ?? cred.user.uid
    const orgRole = await resolveOrgRole(cred.user.uid, orgId, d.role as UserRole, !!d.organizationId)

    const appUser: AuthUser = {
      uid:            cred.user.uid,
      email:          d.email,
      name:           d.name,
      role:           d.role as UserRole,
      orgRole,
      status:         d.status,
      organizationId: orgId,
    }

    await updateDoc(doc(db, 'users', cred.user.uid), { lastLogin: serverTimestamp() })
    setUser(appUser)
    return { role: appUser.role }
  }

  const register = async (
    name: string,
    email: string,
    password: string,
    organization: OrganizationInput | null,
  ): Promise<void> => {
    // Validate before creating the Firebase account, so bad input never leaves
    // behind an account without an organization.
    let org: OrganizationInput | null = null
    if (organization) {
      const checked = validateOrganization(organization)
      if (checked.errors) throw new Error(Object.values(checked.errors)[0])
      org = checked.value
    }

    const cred = await createUserWithEmailAndPassword(auth, email, password)
    const uid  = cred.user.uid

    if (!org) {
      // Invited user: account only. Plan and quota come from the organization
      // they join, never from the user.
      await setDoc(doc(db, 'users', uid), {
        uid, name, email,
        role:      'customer' as UserRole,   // replaced when the invitation is accepted
        status:    'active',
        createdAt: serverTimestamp(),
        lastLogin: serverTimestamp(),
      })
      setUser({ uid, name, email, role: 'customer', orgRole: 'viewer', status: 'active', organizationId: uid })
      return
    }

    // New customer: user, organization and owner membership are written
    // atomically. The organization id is the owner's uid, which is what scopes
    // the users/{orgId}/… data tree. Plan and quota fields are intentionally
    // absent — the backend treats that as the default plan.
    const batch = writeBatch(db)
    batch.set(doc(db, 'users', uid), {
      uid, name, email,
      role:           'team_admin' as UserRole,
      status:         'active',
      organizationId: uid,
      createdAt:      serverTimestamp(),
      lastLogin:      serverTimestamp(),
    })
    batch.set(doc(db, 'organizations', uid), {
      orgId:      uid,
      ownerId:    uid,
      ownerName:  name,
      ownerEmail: email,
      name:       org.name,
      website:    org.website,
      phone:      org.phone,
      createdAt:  serverTimestamp(),
    })
    batch.set(doc(db, 'organizations', uid, 'members', uid), {
      userId: uid, name, email, orgRole: 'admin', status: 'active', joinedAt: serverTimestamp(),
    })
    await batch.commit()
    await registerOrg(uid, uid, org.name).catch(() => {})

    setUser({
      uid, name, email, role: 'team_admin', orgRole: 'admin',
      status: 'active', organizationId: uid,
    })
  }

  const logout = async (): Promise<void> => {
    await signOut(auth)
    setUser(null)
  }

  const resetPassword = async (email: string): Promise<void> => {
    await sendPasswordResetEmail(auth, email)
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        role:    user?.role    ?? null,
        orgRole: user?.orgRole ?? null,
        loading,
        login,
        register,
        logout,
        resetPassword,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
