import type { Assessment } from '../types';

export const KERBEROS_ASSESSMENT: Assessment = {
  id: 'kerberos',
  title: 'Kerberos and DNS service records knowledge check',
  questions: [
    {
      id: 'krb-q-order', kind: 'order', level: 'beginner',
      prompt: 'Put the steps of a Kerberos SSH login from a freshly logged-in workstation in order.',
      items: ['DNS SRV lookup of _kerberos._udp.corp.lab', 'AS exchange: get a TGT (pre-authentication with the password)', 'TGS exchange: get a ticket for host/srv01.corp.lab', 'SSH gssapi-with-mic: present the ticket to sshd', 'sshd decrypts the ticket with its keytab'],
      concepts: ['ad.kerberos', 'ad.dns'],
      explanation: 'Find the KDC, prove the password once (TGT), exchange the TGT for a service ticket, hand that ticket to the service, which checks it with its own key. The KDC is not involved in the last step.',
    },
    {
      id: 'krb-q-srv', kind: 'text', level: 'beginner',
      prompt: 'krb5.conf lists no KDC for CORP.LAB. Which DNS name does the library query (over UDP) to find one?',
      accept: ['_kerberos._udp.corp.lab', '_kerberos._udp.corp.lab.'], placeholder: '_service._proto.domain', concepts: ['ad.dns'],
      explanation: 'SRV records are named _service._protocol.domain; the realm is lower-cased to form the domain. _kerberos._tcp.corp.lab is queried as well; _kerberos-adm._tcp locates kadmind.',
    },
    {
      id: 'krb-q-skew', kind: 'single', level: 'beginner',
      prompt: 'kinit says "Clock skew too great while getting initial credentials". What is the right fix?',
      options: [
        { text: 'Enable NTP on the machine whose clock is wrong (timedatectl set-ntp true)', correct: true },
        { text: 'Raise clockskew in krb5.conf to 3600', misconception: 'That widens the replay window for everyone and leaves the clock wrong (certificates, logs and cron suffer too).' },
        { text: 'Reset alice\'s password', misconception: 'The password was right: the KDC decrypted the timestamp and found it too far from its own time.' },
        { text: 'Restart the KDC', misconception: 'The KDC works; the client\'s time is wrong.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'Kerberos rejects timestamps more than 300 s from the KDC\'s clock. Synchronise clocks; never loosen the tolerance.',
    },
    {
      id: 'krb-q-errors', kind: 'single', level: 'intermediate',
      prompt: 'kinit waits about 10 seconds and then reports "Cannot contact any KDC for realm \'CORP.LAB\'". "host -t SRV _kerberos._udp.corp.lab" answers with ns1. On ns1, krb5-kdc is active and listening on :88, but its log shows no request from you. Most likely cause?',
      options: [
        { text: 'A firewall drops port 88 on the way to (or on) ns1', correct: true },
        { text: 'The SRV records are missing', misconception: 'They resolve; "Cannot find KDC" would be the message without them.' },
        { text: 'The KDC service is stopped', misconception: 'It is listening. A stopped KDC fails fast with ICMP port unreachable, not after a wait.' },
        { text: 'Wrong password', misconception: 'The KDC never received a request, so it never checked a password.' },
      ],
      concepts: ['ad.kerberos', 'fw.stateful'],
      explanation: 'Slow failure = silence = dropped packets. tcpdump on ns1 and nft list ruleset confirm it.',
    },
    {
      id: 'krb-q-kvno', kind: 'single', level: 'intermediate',
      exhibit: 'ws01$ kvno host/srv01.corp.lab\nhost/srv01.corp.lab@CORP.LAB: kvno = 3\n\nsrv01# klist -k\nKeytab name: FILE:/etc/krb5.keytab\nKVNO Principal\n---- ------------------------------------------\n   2 host/srv01.corp.lab@CORP.LAB\n   2 host/srv01.corp.lab@CORP.LAB',
      prompt: 'kinit works, but Kerberos SSH logins to srv01 fail. What does the exhibit show, and how do you fix it?',
      options: [
        { text: 'The KDC encrypts tickets with key version 3, srv01 only has version 2: run "kadmin -p alice/admin -q \\"ktadd host/srv01.corp.lab\\"" on srv01', correct: true },
        { text: 'The client\'s ticket is too new: wait for it to expire', misconception: 'Every new ticket will use kvno 3; the server must get the current key.' },
        { text: 'Delete the host principal and recreate it on the KDC', misconception: 'That changes the key again without giving srv01 the new one.' },
        { text: 'Disable GSSAPIAuthentication and use passwords', misconception: 'That removes single sign-on instead of fixing the keytab.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'The key was changed on the KDC (cpw -randkey or a ktadd elsewhere) without updating srv01\'s keytab. ktadd on the server creates a new key and stores it locally in one step; clients then need fresh tickets (kdestroy; kinit).',
    },
    {
      id: 'krb-q-names', kind: 'multi', level: 'advanced',
      prompt: 'srv01 has only the principal host/srv01.corp.lab. With rdns = false, which of these commands (with a valid TGT) can log in with Kerberos? Select all that apply.',
      options: [
        { text: 'ssh srv01.corp.lab', correct: true },
        { text: 'ssh www.corp.lab (www is a CNAME for srv01)', correct: true },
        { text: 'ssh 10.0.20.10', misconception: 'Without reverse lookups the client asks for host/10.0.20.10, which does not exist.' },
        { text: 'ssh srv01 (search domain corp.lab)', correct: true },
      ],
      concepts: ['ad.kerberos', 'dns.resolution'],
      explanation: 'The client canonicalises the name with forward DNS (search domains, CNAMEs) and asks for host/<canonical name>. IP addresses only work with reverse DNS (rdns = true and correct PTR records) or an extra principal.',
    },
    {
      id: 'krb-q-preauth', kind: 'single', level: 'advanced',
      prompt: 'Why does the KDC answer the first AS-REQ with KDC_ERR_PREAUTH_REQUIRED instead of issuing a TGT right away?',
      options: [
        { text: 'So that nobody can obtain material encrypted with a user\'s key without proving the password first (offline guessing, "AS-REP roasting")', correct: true },
        { text: 'Because the first request is always lost', misconception: 'The KDC answers it; the answer is a request for proof.' },
        { text: 'To find out which KDC is the primary', misconception: 'Pre-authentication is about the client\'s identity, not KDC selection.' },
        { text: 'Because the client did not send its password', misconception: 'The password is never sent; the client proves it by encrypting a timestamp with the derived key.' },
      ],
      concepts: ['ad.kerberos'],
      explanation: 'Without pre-authentication the AS-REP (encrypted with the user\'s key) could be requested by anyone and attacked offline. +preauth makes the client prove knowledge of the key first.',
    },
  ],
};
