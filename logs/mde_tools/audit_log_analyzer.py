
from typing import Counter

class AuditLogAnalyzer:

    def __init__(self) -> None:
        self.syscalls = Counter()
        self.syscall_lines = Counter()

        self.initiators = Counter()
        self.paths = Counter()
        self.keys = Counter()
        self.types = Counter()
        self.syscall_tuples = Counter()

        self.eventid_to_syscall = {}
        self.eventid_to_initiator = {}

        self.syscall_paths = Counter()
        self.syscall_owner_paths = Counter()
    
    def analyze(self, path) -> None:
        with path.open('r', errors='ignore') as log_file:
            for line in log_file:
                pairs = line.rstrip().split(' ')
                
                d = dict(pair.split('=')[-2:] for pair in pairs if '=' in pair)

                evt_id = d.get('msg','None')
                evt_type = d.get('type', 'None')

                self.types[evt_type] += 1

                if evt_type == 'SYSCALL':
                    syscall = d.get('syscall', 'None')
                    initiator = d.get('exe', 'None')
                    self.syscalls[syscall] += 1
                    self.syscall_lines[syscall] += 1
                    self.initiators[initiator] += 1
                    self.keys[d.get('key', 'None')] += 1
                    self.syscall_tuples[(syscall, initiator, d.get('key', 'None'))] +=1
                    self.eventid_to_syscall[evt_id] = syscall
                    self.eventid_to_initiator[evt_id] = initiator

                elif evt_type == 'PATH':
                    path = d.get('name', 'None');
                    self.paths[path] +=1
                    if evt_id in self.eventid_to_syscall:
                        self.syscall_paths[(self.eventid_to_syscall[evt_id], path )] +=1
                        self.syscall_owner_paths[(self.eventid_to_syscall[evt_id], self.eventid_to_initiator[evt_id] , path)] +=1
                        self.syscall_lines[self.eventid_to_syscall[evt_id]] += 1
                else:
                    if evt_id in self.eventid_to_syscall:
                        self.syscall_lines[self.eventid_to_syscall[evt_id]] += 1

    def write_to(self, path) -> None:
        with open(path, 'w') as writer:
            writer.write('\n\nTop keys:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.keys.most_common(10)))
            writer.write('\n\nTop types:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.types.most_common(10)))
            writer.write('\n\nTop syscalls by count:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.syscalls.most_common(10)))
            writer.write('\n\nTop syscalls by lines:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.syscall_lines.most_common(10)))
            writer.write('\n\nTop initiators:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.initiators.most_common(15)))
            writer.write('\n\nTop syscalls by initiator:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.syscall_tuples.most_common(15)))
            writer.write('\n\nTop paths:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.syscall_paths.most_common(15)))
            writer.write('\n\nTop paths by initiator:\n')
            writer.write('\n'.join('{}: {}'.format(entry, count) for entry, count in self.syscall_owner_paths.most_common(15)))
