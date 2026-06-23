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

export type UserRole =
  | 'customer'
  | 'analyst'
  | 'team_admin'
  | 'super_admin'
  | 'platform_admin'

export interface AuthUser {
  uid: string
  email: string
  name: string
  role: UserRole
  status: string
  organizationId: string | null
}

interface AuthContextValue {
  user: AuthUser | null
  role: UserRole | null
  loading: boolean
  login: (email: string, password: string) => Promise<{ role: UserRole }>
  register: (name: string, email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  resetPassword: (email: string) => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

async function fetchUserDoc(firebaseUser: FirebaseUser): Promise<AuthUser | null> {
  try {
    const snap = await getDoc(doc(db, 'users', firebaseUser.uid))
    if (!snap.exists()) return null
    const d = snap.data()
    return {
      uid: firebaseUser.uid,
      email: d.email,
      name: d.name,
      role: d.role as UserRole,
      status: d.status,
      organizationId: d.organizationId ?? null,
    }
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        const appUser = await fetchUserDoc(firebaseUser)
        setUser(appUser)
      } else {
        setUser(null)
      }
      setLoading(false)
    })
    return unsubscribe
  }, [])

  const login = async (email: string, password: string): Promise<{ role: UserRole }> => {
    const cred = await signInWithEmailAndPassword(auth, email, password)
    const snap = await getDoc(doc(db, 'users', cred.user.uid))

    if (!snap.exists()) {
      await signOut(auth)
      throw new Error('User account not found. Please contact support.')
    }

    const d = snap.data()
    const appUser: AuthUser = {
      uid: cred.user.uid,
      email: d.email,
      name: d.name,
      role: d.role as UserRole,
      status: d.status,
      organizationId: d.organizationId ?? null,
    }

    await updateDoc(doc(db, 'users', cred.user.uid), {
      lastLogin: serverTimestamp(),
    })

    setUser(appUser)
    return { role: appUser.role }
  }

  const register = async (
    name: string,
    email: string,
    password: string,
  ): Promise<void> => {
    const cred = await createUserWithEmailAndPassword(auth, email, password)
    const userData = {
      uid: cred.user.uid,
      name,
      email,
      role: 'customer' as UserRole,
      status: 'active',
      organizationId: null,
      createdAt: serverTimestamp(),
      lastLogin: serverTimestamp(),
    }
    await setDoc(doc(db, 'users', cred.user.uid), userData)
    setUser({
      uid: cred.user.uid,
      name,
      email,
      role: 'customer',
      status: 'active',
      organizationId: null,
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
        role: user?.role ?? null,
        loading,
        login,
        register,
        logout,
        resetPassword,
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
