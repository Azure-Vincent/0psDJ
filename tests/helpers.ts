import { buildSshLab } from '../src/engine/lab/sshLab';
import { Shell } from '../src/engine/shell/shell';
import type { World } from '../src/engine/types';

export class Lab {
  world: World;
  constructor(world?: World) {
    this.world = world ?? buildSshLab();
  }
  shell(hostId: string, user: string, cwd?: string): Shell {
    const home = this.world.hosts[hostId].users[user].home;
    return new Shell(() => this.world, (w) => (this.world = w), { hostId, user, cwd: cwd ?? home });
  }
  run(hostId: string, user: string, line: string, answers: string[] = []) {
    return this.shell(hostId, user).execute(line, answers);
  }
}
