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
} from 'firebase/firestore'
import { auth, db } from '@/lib/firebase'
import type { OrgRole } from '@/lib/rbac'
import { platformRoleToOrgRole } from '@/lib/rbac'
import { createOrg, addMember, getMember } from '@/lib/firestore-team'
import { registerOrg } from '@/lib/api-team'

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
  register:      (name: string, email: string, password: string) => Promise<void>
  logout:        () => Promise<void>
  resetPassword: (email: string) => Promise<void>
  refreshUser:   () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

async function resolveOrgRole(uid: string, organizationId: string, platformRole: UserRole): Promise<OrgRole> {
  // Owner of their own workspace is always admin
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
    const orgRole = await resolveOrgRole(firebaseUser.uid, orgId, d.role as UserRole)
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

async function ensureOrgExists(uid: string, name: string, email: string): Promise<void> {
  try {
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
    const orgRole = await resolveOrgRole(cred.user.uid, orgId, d.role as UserRole)

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

  const register = async (name: string, email: string, password: string): Promise<void> => {
    const cred = await createUserWithEmailAndPassword(auth, email, password)
    const userData = {
      uid:            cred.user.uid,
      name,
      email,
      role:           'team_admin' as UserRole,  // every new user is admin of their own workspace
      status:         'active',
      organizationId: cred.user.uid,             // own workspace
      createdAt:      serverTimestamp(),
      lastLogin:      serverTimestamp(),
    }
    await setDoc(doc(db, 'users', cred.user.uid), userData)

    const orgName = `${name}'s Workspace`
    await createOrg({ orgId: cred.user.uid, ownerId: cred.user.uid, ownerName: name, ownerEmail: email, name: orgName, createdAt: '' as any })
    await addMember(cred.user.uid, {
      userId: cred.user.uid, name, email, orgRole: 'admin', status: 'active', joinedAt: '' as any,
    })
    await registerOrg(cred.user.uid, cred.user.uid, orgName).catch(() => {})

    setUser({
      uid: cred.user.uid, name, email, role: 'team_admin', orgRole: 'admin',
      status: 'active', organizationId: cred.user.uid,
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
