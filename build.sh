gcc monitor.c env.c proc.c fuzz.c -g -o monitor
gcc fuzz_pid.c env.c proc.c fuzz.c -g -o fuzz_pid

cd afl-nocoo
make -j8
cp afl-fuzz ../
echo "copy afl-fuzz"
cd ..

cd qemu-nocoo
make -j8
cp x86_64-linux-user/qemu-x86_64 ../afl-qemu-trace
echo "copy qemu-x86_64"
cd ..
