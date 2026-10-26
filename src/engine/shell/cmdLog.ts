// logger (util-linux 2.38) and rsyslogd -N1 (configuration check).

import { log } from '../sim/journal';
import { isFacility, loadRsyslog, RSYSLOG_VERSION, sendSyslog, severityOf } from '../sim/syslog';
import { type CommandDef, err, ok, parseFlags } from './types';

const logger: CommandDef = {
  name: 'logger',
  summary: 'write a message to the system log (journal and syslog), or send it to a syslog server',
  usage: 'logger [-p FACILITY.LEVEL] [-t TAG] [-i] [-n SERVER [-P PORT] [-T|-d]] MESSAGE',
  run(args, ctx) {
    const { flags, rest } = parseFlags(args, ['-p', '-t', '-n', '-P', '--priority', '--tag', '--server', '--port']);
    const p = (flags.get('-p') ?? flags.get('--priority')) as string | undefined;
    let facility = 'user';
    let severity = severityOf('notice')!;
    if (p) {
      const [f, l] = p.includes('.') ? p.split('.') : ['user', p];
      const sev = severityOf(l);
      if (!isFacility(f)) return err(`logger: unknown facility name: ${f}`, 1);
      if (!sev) return err(`logger: unknown priority name: ${l}`, 1);
      facility = f;
      severity = sev;
    }
    const tag = ((flags.get('-t') ?? flags.get('--tag')) as string | undefined) ?? ctx.user.name;
    const text = rest.join(' ');
    if (!text) return err('logger: no message given (reading from standard input is not simulated)', 1);
    const server = (flags.get('-n') ?? flags.get('--server')) as string | undefined;
    if (server) {
      const port = Number((flags.get('-P') ?? flags.get('--port')) ?? 514);
      const e = sendSyslog(ctx.world, ctx.host, flags.has('-T') ? 'tcp' : 'udp', server, port, { time: ctx.world.clock, hostname: ctx.host.hostname, program: tag, pid: null, facility, severity, text, fromIp: '' });
      return e ? err(e, 1) : ok('');
    }
    log(ctx.world, ctx.host, tag, text, { pid: flags.has('-i') ? 4000 + (ctx.world.counter % 1000) : null, priority: severity, facility });
    return ok('');
  },
};

const rsyslogd: CommandDef = {
  name: 'rsyslogd',
  summary: 'rsyslog daemon: -N1 checks the configuration',
  usage: 'rsyslogd -N1 | rsyslogd -v',
  run(args, ctx) {
    if (!ctx.host.services.rsyslog) return err('-bash: rsyslogd: command not found', 127);
    if (args.includes('-v') || args.includes('--version')) return ok(`rsyslogd  ${RSYSLOG_VERSION} (aka 2023.02) compiled with:\n\tPLATFORM:\t\t\t\tx86_64-pc-linux-gnu\n\tFEATURE_REGEXP:\t\t\t\tYes\n\tGSSAPI Kerberos 5 support:\t\tYes\n\tFEATURE_DEBUG (debug build, slow code):\tNo\n\t32bit Atomic operations supported:\tYes\n\t64bit Atomic operations supported:\tYes\n\tmemory allocator:\t\t\tsystem default\n\tRuntime Instrumentation (slow code):\tNo\n\tuuid support:\t\t\t\tYes\n\tsystemd support:\t\t\tYes\n\tConfig file:\t\t\t\t/etc/rsyslog.conf\n\tPID file:\t\t\t\t/run/rsyslogd.pid\n\tNumber of Bits in RainerScript integers: 64\n\nSee https://www.rsyslog.com for more information.`);
    if (!args.some((a) => /^-N\d?$/.test(a))) return err('rsyslogd: this simulator supports -N1 (check the configuration) and -v', 1);
    if (ctx.user.uid !== 0) return err('rsyslogd: error accessing config file or directory \'/etc/rsyslog.conf\': Permission denied', 1);
    const l = loadRsyslog(ctx.host);
    const head = `rsyslogd: version ${RSYSLOG_VERSION}, config validation run (level 1), master config /etc/rsyslog.conf`;
    if (l.errors.length) return err([head, ...l.errors.map((e) => `rsyslogd: ${e}`)].join('\n'), 1);
    return ok(`${head}\nrsyslogd: End of config validation run. Bye.`);
  },
};

export const LOG_COMMANDS: CommandDef[] = [logger, rsyslogd];
