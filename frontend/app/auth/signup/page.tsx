'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Check } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useAuth } from '@/context/auth-context'
import { validateOrganization, type OrganizationInput } from '@/lib/org-validation'

type Step = 0 | 1 | 2
const STEPS = ['Account', 'Organization', 'Review'] as const

function Field({
  label, error, children,
}: { label: string; error?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-sm font-medium text-foreground mb-2">{label}</label>
      {children}
      {error && <p className="text-xs text-destructive mt-1.5">{error}</p>}
    </div>
  )
}

export default function SignupPage() {
  const router = useRouter()
  const { register } = useAuth()
  const [step, setStep] = useState<Step>(0)

  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const [org, setOrg] = useState<OrganizationInput>({ name: '', website: '', phone: '' })
  const [orgErrors, setOrgErrors] = useState<Partial<Record<keyof OrganizationInput, string>>>({})
  const [cleanOrg, setCleanOrg] = useState<OrganizationInput | null>(null)

  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const inputCls = 'bg-background/50 border-foreground/20'

  function nextFromAccount(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (password !== confirmPassword) { setError('Passwords do not match.'); return }
    if (password.length < 6) { setError('Password must be at least 6 characters.'); return }
    setStep(1)
  }

  function nextFromOrganization(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    const checked = validateOrganization(org)
    if (checked.errors) { setOrgErrors(checked.errors); return }
    setOrgErrors({})
    setCleanOrg(checked.value)
    setStep(2)
  }

  const handleCreate = async () => {
    if (!cleanOrg) { setStep(1); return }
    setError('')
    setIsLoading(true)
    try {
      await register(name.trim(), email.trim(), password, cleanOrg)
      router.push('/app/dashboard')
    } catch (err: any) {
      const code = err?.code ?? ''
      if (code === 'auth/email-already-in-use') {
        setError('An account with this email already exists.')
        setStep(0)
      } else if (code === 'auth/invalid-email') {
        setError('Please enter a valid email address.')
        setStep(0)
      } else if (code === 'auth/weak-password') {
        setError('Password must be at least 6 characters.')
        setStep(0)
      } else {
        setError(err?.message || 'Registration failed. Please try again.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-secondary px-4">
      <div className="w-full max-w-md">
        <div className="border border-foreground/10 rounded-xl p-8 bg-card backdrop-blur-sm">
          <div className="text-center mb-6">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Vectra
            </h1>
            <p className="text-sm text-muted-foreground mt-2">Create your organization&apos;s workspace</p>
          </div>

          {/* Stepper */}
          <ol className="flex items-center justify-between mb-6">
            {STEPS.map((label, i) => (
              <li key={label} className="flex items-center gap-2 flex-1 last:flex-none">
                <span className={`flex items-center justify-center w-6 h-6 rounded-full text-[11px] font-semibold border ${
                  i < step ? 'bg-primary text-primary-foreground border-primary'
                  : i === step ? 'border-primary text-primary'
                  : 'border-foreground/20 text-muted-foreground'
                }`}>
                  {i < step ? <Check className="w-3.5 h-3.5" /> : i + 1}
                </span>
                <span className={`text-xs ${i === step ? 'text-foreground font-medium' : 'text-muted-foreground'}`}>{label}</span>
                {i < STEPS.length - 1 && <span className="flex-1 h-px bg-foreground/10 mx-2" />}
              </li>
            ))}
          </ol>

          {error && (
            <div className="mb-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
              {error}
            </div>
          )}

          {step === 0 && (
            <form onSubmit={nextFromAccount} className="space-y-5">
              <Field label="Full Name">
                <Input type="text" placeholder="John Doe" value={name} onChange={(e) => setName(e.target.value)} required className={inputCls} autoComplete="name" />
              </Field>
              <Field label="Email Address">
                <Input type="email" placeholder="you@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required className={inputCls} autoComplete="email" />
              </Field>
              <Field label="Password">
                <Input type="password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} required className={inputCls} autoComplete="new-password" />
              </Field>
              <Field label="Confirm Password">
                <Input type="password" placeholder="••••••••" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required className={inputCls} autoComplete="new-password" />
              </Field>
              <Button type="submit" className="w-full bg-primary hover:bg-primary/90 text-primary-foreground h-11 rounded-lg">
                Continue
              </Button>
            </form>
          )}

          {step === 1 && (
            <form onSubmit={nextFromOrganization} className="space-y-5" noValidate>
              <Field label="Organization Name" error={orgErrors.name}>
                <Input type="text" placeholder="Acme Technologies" value={org.name} maxLength={100}
                  onChange={(e) => setOrg({ ...org, name: e.target.value })} className={inputCls} autoComplete="organization" />
              </Field>
              <Field label="Website URL" error={orgErrors.website}>
                <Input type="url" placeholder="https://acme.com" value={org.website} maxLength={200}
                  onChange={(e) => setOrg({ ...org, website: e.target.value })} className={inputCls} autoComplete="url" />
              </Field>
              <Field label="Contact Phone" error={orgErrors.phone}>
                <Input type="tel" placeholder="+1 555 123 4567" value={org.phone} maxLength={20}
                  onChange={(e) => setOrg({ ...org, phone: e.target.value })} className={inputCls} autoComplete="tel" />
              </Field>
              <div className="flex gap-2">
                <Button type="button" variant="outline" className="flex-1 h-11 rounded-lg border-foreground/20" onClick={() => setStep(0)}>
                  Back
                </Button>
                <Button type="submit" className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground h-11 rounded-lg">
                  Continue
                </Button>
              </div>
            </form>
          )}

          {step === 2 && cleanOrg && (
            <div className="space-y-5">
              <div className="rounded-lg border border-foreground/10 divide-y divide-foreground/10 text-sm">
                {[
                  ['Name', name.trim()],
                  ['Email', email.trim()],
                  ['Organization', cleanOrg.name],
                  ['Website', cleanOrg.website],
                  ['Phone', cleanOrg.phone],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-4 px-3 py-2.5">
                    <span className="text-muted-foreground">{k}</span>
                    <span className="text-foreground text-right break-all">{v}</span>
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                You&apos;ll be the owner of this organization. It starts on the Free plan, and its scan
                allowance is shared by everyone you invite.
              </p>
              <div className="flex gap-2">
                <Button type="button" variant="outline" className="flex-1 h-11 rounded-lg border-foreground/20"
                  onClick={() => setStep(1)} disabled={isLoading}>
                  Back
                </Button>
                <Button onClick={handleCreate} loading={isLoading} loadingText="Creating…"
                  className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground h-11 rounded-lg">
                  Create Account
                </Button>
              </div>
            </div>
          )}

          <p className="mt-6 text-center text-sm text-muted-foreground">
            Already have an account?{' '}
            <Link href="/auth/login" className="text-primary hover:text-primary/90 font-medium">
              Sign in
            </Link>
          </p>
        </div>

        <div className="mt-6 text-center">
          <Link href="/" className="text-sm text-muted-foreground hover:text-foreground">
            ← Back to home
          </Link>
        </div>
      </div>
    </div>
  )
}
