gcc monitor.c env.c proc.c fuzz.c -g -o monitor
gcc fuzz_pid.c env.c proc.c fuzz.c -g -o fuzz_pid
