/**
 * Behavioural verification of Vectra's Firestore rules.
 *
 * Compiling proves syntax; this proves the security properties actually hold —
 * above all that a signed-in user cannot lift their own scan quota or promote
 * themselves to platform admin.
 */
import fs from 'node:fs'
import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} from '@firebase/rules-unit-testing'
import { doc, getDoc, setDoc, updateDoc, collection, getDocs, writeBatch } from 'firebase/firestore'

const OWNER  = 'owner-uid'      // owns org "owner-uid"
const MEMBER = 'member-uid'     // active member of that org
const OUTSIDER = 'outsider-uid' // no membership anywhere
const ADMIN  = 'admin-uid'      // platform_admin

const results = []
const record = (name, ok, note = '') => {
  results.push({ name, ok, note })
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${note ? '  — ' + note : ''}`)
}

async function expectDenied(name, op) {
  try { await assertFails(op); record(name, true) }
  catch (e) { record(name, false, 'was ALLOWED but must be denied') }
}
async function expectAllowed(name, op) {
  try { await assertSucceeds(op); record(name, true) }
  catch (e) { record(name, false, `was DENIED: ${String(e).slice(0, 90)}`) }
}

const env = await initializeTestEnvironment({
  projectId: 'vectra-rules-validation',
  firestore: { rules: fs.readFileSync('firestore.rules', 'utf8'), host: '127.0.0.1', port: 8571 },
})

// ── Seed baseline data with rules bypassed ───────────────────────────
await env.withSecurityRulesDisabled(async (ctx) => {
  const db = ctx.firestore()
  await setDoc(doc(db, 'organizations', OWNER), {
    orgId: OWNER, ownerId: OWNER, ownerName: 'Owner', ownerEmail: 'o@x.io', name: 'Acme',
  })
  await setDoc(doc(db, 'organizations', OWNER, 'members', OWNER),
    { userId: OWNER, name: 'Owner', email: 'o@x.io', orgRole: 'admin', status: 'active' })
  await setDoc(doc(db, 'organizations', OWNER, 'members', MEMBER),
    { userId: MEMBER, name: 'Member', email: 'm@x.io', orgRole: 'editor', status: 'active' })

  await setDoc(doc(db, 'users', MEMBER), {
    uid: MEMBER, name: 'Member', email: 'm@x.io', role: 'analyst', status: 'active',
    organizationId: OWNER, plan: 'free', bonusScans: 0, scansUsed: 2,
  })
  await setDoc(doc(db, 'users', ADMIN), {
    uid: ADMIN, name: 'Admin', email: 'a@x.io', role: 'platform_admin', status: 'active',
    organizationId: ADMIN, plan: 'free', bonusScans: 0, scansUsed: 0,
  })
  await setDoc(doc(db, 'users', 'disabled-uid'), {
    uid: 'disabled-uid', name: 'Disabled', email: 'd@x.io', role: 'customer',
    status: 'disabled', organizationId: 'disabled-uid', plan: 'free', bonusScans: 0, scansUsed: 3,
  })
  await setDoc(doc(db, 'users', OWNER, 'scans', 'scan1'), { scanId: 'scan1', target: 'example.com' })
  await setDoc(doc(db, 'platform_config', 'quota'), { planAllowances: { free: 3 } })
  await setDoc(doc(db, 'invitationTokens', 'secret-token'), { token: 'secret-token', orgId: OWNER, inviteId: 'inv1', type: 'link' })
  await setDoc(doc(db, 'organizations', OWNER, 'invitations', 'inv1'), {
    inviteId: 'inv1', orgRole: 'editor', status: 'pending', invitedBy: OWNER, usedCount: 0,
  })
})

const member   = env.authenticatedContext(MEMBER).firestore()
const outsider = env.authenticatedContext(OUTSIDER).firestore()
const owner    = env.authenticatedContext(OWNER).firestore()
const admin    = env.authenticatedContext(ADMIN).firestore()
const anon     = env.unauthenticatedContext().firestore()

console.log('\n[1] SCAN QUOTA CANNOT BE SELF-SERVED  (the critical property)')
await expectDenied('user cannot raise own bonusScans',
  updateDoc(doc(member, 'users', MEMBER), { bonusScans: 9999 }))
await expectDenied('user cannot reset own scansUsed',
  updateDoc(doc(member, 'users', MEMBER), { scansUsed: 0 }))
await expectDenied('user cannot upgrade own plan',
  updateDoc(doc(member, 'users', MEMBER), { plan: 'enterprise' }))
await expectDenied('DISABLED user cannot re-enable themselves',
  updateDoc(doc(env.authenticatedContext('disabled-uid').firestore(), 'users', 'disabled-uid'),
            { status: 'active' }))
await expectDenied('user cannot suspend/alter own status value',
  updateDoc(doc(member, 'users', MEMBER), { status: 'suspended' }))
await expectDenied('user cannot smuggle quota alongside a legit field',
  updateDoc(doc(member, 'users', MEMBER), { name: 'New Name', scansUsed: 0 }))

console.log('\n[2] NO PRIVILEGE ESCALATION')
await expectDenied('user cannot self-promote to platform_admin',
  updateDoc(doc(member, 'users', MEMBER), { role: 'platform_admin' }))
await expectDenied('user cannot self-promote to super_admin',
  updateDoc(doc(member, 'users', MEMBER), { role: 'super_admin' }))
await expectDenied('signup cannot mint a platform_admin',
  setDoc(doc(outsider, 'users', OUTSIDER), {
    uid: OUTSIDER, name: 'X', email: 'x@x.io', role: 'platform_admin',
    status: 'active', organizationId: OUTSIDER,
  }))
await expectDenied('signup cannot seed its own quota',
  setDoc(doc(outsider, 'users', OUTSIDER), {
    uid: OUTSIDER, name: 'X', email: 'x@x.io', role: 'team_admin',
    status: 'active', organizationId: OUTSIDER, bonusScans: 500,
  }))

console.log('\n[3] LEGITIMATE FLOWS STILL WORK')
await expectAllowed('normal signup',
  setDoc(doc(outsider, 'users', OUTSIDER), {
    uid: OUTSIDER, name: 'X', email: 'x@x.io', role: 'team_admin',
    status: 'active', organizationId: OUTSIDER,
  }))
await expectAllowed('user updates own lastLogin',
  updateDoc(doc(member, 'users', MEMBER), { lastLogin: new Date().toISOString() }))
await expectAllowed('platform_admin updates own lastLogin (regression)',
  updateDoc(doc(admin, 'users', ADMIN), { lastLogin: new Date().toISOString() }))
await expectAllowed('invite accept sets org + assignable role',
  updateDoc(doc(member, 'users', MEMBER), { organizationId: OWNER, role: 'analyst' }))

console.log('\n[4] ORGANIZATION ISOLATION')
await expectAllowed('member reads org scan data',
  getDoc(doc(member, 'users', OWNER, 'scans', 'scan1')))
await expectAllowed('member writes org scan data',
  setDoc(doc(member, 'users', OWNER, 'findings', 'f1'), { findingId: 'f1', severity: 'high' }))
await expectDenied('outsider CANNOT read another org\'s scans',
  getDoc(doc(outsider, 'users', OWNER, 'scans', 'scan1')))
await expectDenied('outsider CANNOT write to another org',
  setDoc(doc(outsider, 'users', OWNER, 'findings', 'evil'), { findingId: 'evil' }))
await expectDenied('outsider CANNOT read another user\'s profile',
  getDoc(doc(outsider, 'users', MEMBER)))

console.log('\n[5] BACKEND-ONLY COLLECTIONS ARE CLOSED TO CLIENTS')
await expectDenied('client cannot read platform_config',
  getDoc(doc(member, 'platform_config', 'quota')))
await expectDenied('client cannot raise the global allowance',
  setDoc(doc(member, 'platform_config', 'quota'), { planAllowances: { free: 9999 } }))
await expectDenied('platform_admin client cannot read platform_config either',
  getDoc(doc(admin, 'platform_config', 'quota')))
await expectDenied('client cannot read platform audit log',
  getDoc(doc(member, 'platform_audit_logs', 'anything')))

console.log('\n[6] INVITE FLOW WORKS PRE-AUTH, WITHOUT ENUMERATION')
await expectAllowed('anonymous resolves invite token',
  getDoc(doc(anon, 'invitationTokens', 'secret-token')))
await expectAllowed('anonymous reads the single invite doc',
  getDoc(doc(anon, 'organizations', OWNER, 'invitations', 'inv1')))
await expectAllowed('anonymous reads org name',
  getDoc(doc(anon, 'organizations', OWNER)))
await expectDenied('anonymous CANNOT list all invitations',
  getDocs(collection(anon, 'organizations', OWNER, 'invitations')))
await expectDenied('outsider CANNOT list org members',
  getDocs(collection(outsider, 'organizations', OWNER, 'members')))

console.log('\n[7] ORG ROLE BOUNDARIES')
await expectDenied('non-admin member cannot change another member\'s role',
  updateDoc(doc(member, 'organizations', OWNER, 'members', OWNER), { orgRole: 'viewer' }))
await expectDenied('member cannot self-promote to org admin',
  updateDoc(doc(member, 'organizations', OWNER, 'members', MEMBER), { orgRole: 'admin' }))
await expectAllowed('org admin can change a member role',
  updateDoc(doc(owner, 'organizations', OWNER, 'members', MEMBER), { orgRole: 'viewer' }))
await expectDenied('audit log entries cannot be rewritten',
  env.withSecurityRulesDisabled(async (ctx) => {
    await setDoc(doc(ctx.firestore(), 'organizations', OWNER, 'auditLogs', 'log1'), { logId: 'log1' })
  }).then(() => updateDoc(doc(member, 'organizations', OWNER, 'auditLogs', 'log1'), { logId: 'tampered' })))

console.log('\n[8] ORGANIZATION PLAN & SHARED QUOTA ARE BACKEND-ONLY')
for (const [field, value] of [['bonusScans', 9999], ['scansUsed', 0], ['plan', 'enterprise'], ['status', 'active'], ['quotaMigratedAt', 'x']]) {
  await expectDenied(`org ADMIN cannot set organization ${field}`,
    updateDoc(doc(owner, 'organizations', OWNER), { [field]: value }))
}
await expectDenied('org admin cannot smuggle quota alongside a profile edit',
  updateDoc(doc(owner, 'organizations', OWNER), { name: 'Acme 2', scansUsed: 0 }))
await expectDenied('org admin cannot transfer ownership',
  updateDoc(doc(owner, 'organizations', OWNER), { ownerId: MEMBER }))
await expectDenied('non-admin member cannot edit organization profile',
  updateDoc(doc(member, 'organizations', OWNER), { name: 'Hijacked' }))
await expectAllowed('org admin edits organization profile',
  updateDoc(doc(owner, 'organizations', OWNER), { name: 'Acme Technologies', website: 'https://acme.com', phone: '+1 555 123 4567' }))
await expectDenied('org admin cannot set a javascript: website',
  updateDoc(doc(owner, 'organizations', OWNER), { website: 'javascript:alert(1)' }))
await expectDenied('member cannot read scan claims',
  getDocs(collection(member, 'organizations', OWNER, 'scanClaims')))
await expectDenied('org admin cannot write scan claims',
  setDoc(doc(owner, 'organizations', OWNER, 'scanClaims', 'c1'), { uid: OWNER }))

const NEWCO = 'newco-uid'
const newco = env.authenticatedContext(NEWCO).firestore()
const orgBody = (extra = {}) => ({
  orgId: NEWCO, ownerId: NEWCO, ownerName: 'New', ownerEmail: 'n@x.io',
  name: 'NewCo', website: 'https://newco.io', phone: '+44 20 7946 0958', ...extra,
})
await expectDenied('signup cannot seed organization plan',
  setDoc(doc(newco, 'organizations', NEWCO), orgBody({ plan: 'enterprise' })))
await expectDenied('signup cannot seed organization bonusScans',
  setDoc(doc(newco, 'organizations', NEWCO), orgBody({ bonusScans: 100 })))
await expectDenied('signup cannot seed organization status',
  setDoc(doc(newco, 'organizations', NEWCO), orgBody({ status: 'active' })))
await expectDenied('signup rejects invalid phone',
  setDoc(doc(newco, 'organizations', NEWCO), orgBody({ phone: 'call me' })))
await expectDenied('signup rejects non-http website',
  setDoc(doc(newco, 'organizations', NEWCO), orgBody({ website: 'ftp://newco.io' })))
await expectDenied('signup cannot create an organization for someone else',
  setDoc(doc(newco, 'organizations', 'someone-else'), orgBody({ orgId: 'someone-else' })))
await expectAllowed('new customer signup: user + organization + owner membership (one batch)',
  (() => {
    const batch = writeBatch(newco)
    batch.set(doc(newco, 'users', NEWCO), {
      uid: NEWCO, name: 'New', email: 'n@x.io', role: 'team_admin', status: 'active', organizationId: NEWCO,
    })
    batch.set(doc(newco, 'organizations', NEWCO), orgBody())
    batch.set(doc(newco, 'organizations', NEWCO, 'members', NEWCO), {
      userId: NEWCO, name: 'New', email: 'n@x.io', orgRole: 'admin', status: 'active',
    })
    return batch.commit()
  })())
await expectAllowed('invited signup: account only, no organization',
  setDoc(doc(env.authenticatedContext('invitee-uid').firestore(), 'users', 'invitee-uid'), {
    uid: 'invitee-uid', name: 'Invitee', email: 'i@x.io', role: 'customer', status: 'active',
  }))

console.log('\n[9] CLOUD SECURITY DATA IS BACKEND-ONLY')
await env.withSecurityRulesDisabled(async (ctx) => {
  const db = ctx.firestore()
  await setDoc(doc(db, 'organizations', OWNER, 'cloud_integrations', 'cint1'), { integrationId: 'cint1', provider: 'aws', status: 'connected' })
  await setDoc(doc(db, 'organizations', OWNER, 'cloud_secrets', 'cint1'), { envelope: { ciphertext: 'x' } })
  await setDoc(doc(db, 'organizations', OWNER, 'cloud_findings', 'f1'), { title: 'x', severity: 'high' })
  await setDoc(doc(db, 'organizations', OWNER, 'cloud_assets', 'a1'), { resourceId: 'r' })
  await setDoc(doc(db, 'organizations', OWNER, 'cloud_syncs', 's1'), { status: 'completed' })
})
for (const [who, client] of [['org admin', owner], ['member', member], ['outsider', outsider], ['anonymous', anon]]) {
  for (const col of ['cloud_integrations', 'cloud_secrets', 'cloud_findings', 'cloud_assets', 'cloud_syncs']) {
    const id = { cloud_integrations: 'cint1', cloud_secrets: 'cint1', cloud_findings: 'f1', cloud_assets: 'a1', cloud_syncs: 's1' }[col]
    await expectDenied(`${who} cannot read ${col}`, getDoc(doc(client, 'organizations', OWNER, col, id)))
  }
}
await expectDenied('org admin cannot list encrypted cloud secrets',
  getDocs(collection(owner, 'organizations', OWNER, 'cloud_secrets')))
await expectDenied('org admin cannot forge a connected integration',
  setDoc(doc(owner, 'organizations', OWNER, 'cloud_integrations', 'forged'), { status: 'connected', provider: 'aws' }))
await expectDenied('org admin cannot inject cloud findings',
  setDoc(doc(owner, 'organizations', OWNER, 'cloud_findings', 'fake'), { title: 'fake', severity: 'critical' }))
await expectDenied('org admin cannot tamper with sync status',
  updateDoc(doc(owner, 'organizations', OWNER, 'cloud_syncs', 's1'), { status: 'running' }))

await env.cleanup()

const failed = results.filter((r) => !r.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
if (failed.length) {
  console.log('FAILED:')
  failed.forEach((f) => console.log(`  - ${f.name}: ${f.note}`))
  process.exit(1)
}
console.log('ALL FIRESTORE RULE CHECKS PASSED')
