import type { ReactNode } from 'react'

/** Minimal layout for public invite pages — no sidebar, no breadcrumb. */
export default function InviteLayout({ children }: { children: ReactNode }) {
  return <>{children}</>
}
