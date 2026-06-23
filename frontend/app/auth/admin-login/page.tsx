'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Shield, Lock, ChevronRight, AlertTriangle } from 'lucide-react'
import { useAuth } from '@/context/auth-context'

const ADMIN_ROLES = ['super_admin', 'platform_admin']

export default function AdminLoginPage() {
  const router = useRouter()
  const { login, logout } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    try {
      const { role } = await login(email, password)

      if (!ADMIN_ROLES.includes(role)) {
        await logout()
        setError('Access denied. This portal is restricted to platform administrators.')
        setIsLoading(false)
        return
      }

      router.push('/admin/dashboard')
    } catch (err: any) {
      const code = err?.code ?? ''
      if (
        code === 'auth/user-not-found' ||
        code === 'auth/wrong-password' ||
        code === 'auth/invalid-credential'
      ) {
        setError('Invalid credentials or insufficient privileges.')
      } else if (code === 'auth/too-many-requests') {
        setError('Too many failed attempts. Please try again later.')
      } else {
        setError(err?.message || 'Authentication failed. Please try again.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex bg-background">
      {/* Left panel */}
      <div className="hidden lg:flex flex-col justify-between w-[42%] bg-gradient-to-br from-foreground/5 via-primary/5 to-accent/10 border-r border-foreground/10 p-12">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary to-accent flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary-foreground" />
          </div>
          <div>
            <p className="font-bold text-foreground text-lg leading-none">Vectra</p>
            <p className="text-xs text-muted-foreground">Admin Console</p>
          </div>
        </div>

        <div className="space-y-8">
          <div>
            <div className="inline-flex items-center gap-2 text-xs font-semibold text-primary bg-primary/10 px-3 py-1.5 rounded-full mb-6">
              <Lock className="w-3 h-3" />
              Restricted Access — Authorized Personnel Only
            </div>
            <h2 className="text-4xl font-bold text-foreground leading-tight mb-4">
              Platform<br />Administration<br />Console
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              Manage the entire Vectra platform — organizations, users, subscriptions, global scans, and infrastructure health from a single control plane.
            </p>
          </div>

          <div className="space-y-4">
            {[
              { label: 'Multi-tenant Organization Management', desc: 'Manage all customer orgs and their data' },
              { label: 'Platform-wide Security Monitoring', desc: 'Global visibility across all findings and scans' },
              { label: 'Subscription & Billing Control', desc: 'Manage plans, MRR, and account lifecycle' },
              { label: 'Infrastructure Health Dashboard', desc: 'Real-time service status and uptime monitoring' },
            ].map((item) => (
              <div key={item.label} className="flex items-start gap-3">
                <ChevronRight className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium text-foreground">{item.label}</p>
                  <p className="text-xs text-muted-foreground">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <p className="text-xs text-muted-foreground">
          © 2026 Vectra Security Inc. — Internal Use Only
        </p>
      </div>

      {/* Right panel — form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center">
              <Shield className="w-4 h-4 text-primary-foreground" />
            </div>
            <span className="font-bold text-foreground">Vectra Admin Console</span>
          </div>

          <div className="mb-8">
            <h1 className="text-2xl font-bold text-foreground mb-2">Sign in to Admin Console</h1>
            <p className="text-sm text-muted-foreground">
              Access restricted to Super Admins and Platform Administrators.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="flex items-center gap-3 p-3.5 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Email Address</label>
              <Input
                type="email"
                placeholder="admin@vectra.io"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="bg-foreground/5 border-foreground/20 rounded-lg h-11"
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Password</label>
              <Input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="bg-foreground/5 border-foreground/20 rounded-lg h-11"
              />
            </div>

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground h-11 rounded-lg font-medium"
            >
              {isLoading ? 'Authenticating...' : 'Sign In to Admin Console'}
            </Button>
          </form>

          <div className="mt-6 text-center space-y-2">
            <p className="text-xs text-muted-foreground">
              Customer login?{' '}
              <Link href="/auth/login" className="text-primary hover:text-primary/80">
                Go to customer portal →
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
