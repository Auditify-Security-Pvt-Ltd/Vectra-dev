# Firestore rules test suite

Verifies `firestore.rules` behaviourally against the real Firestore emulator —
compiling only proves syntax, not that the security properties hold.

## Run

    cd scripts/firestore-rules-test
    npm install @firebase/rules-unit-testing firebase
    cp ../../firestore.rules .
    npx firebase-tools emulators:exec --only firestore \
      --project vectra-rules-validation "node rules.test.mjs"

Requires Java (Firestore emulator).

## What it covers

1. Scan quota cannot be self-served (plan / bonusScans / scansUsed)
2. No privilege escalation to platform_admin / super_admin
3. Legitimate flows still work (signup, lastLogin, invite accept)
4. Organization isolation
5. Backend-only collections closed to all clients
6. Invite flow works pre-auth without enabling enumeration
7. Organization role boundaries + append-only audit log

Re-run after changing the rules or the data model.
