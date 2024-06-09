set -xe

for arch in x86_64 i686
do
	min_hook_lib="MinHook.x86"
	if [ ${arch} == x86_64 ]
	then
		min_hook_lib="MinHook.x64"
	fi

	CPPC=${arch}-w64-mingw32-g++
	$CPPC -g -fPIC -c winhttp_tapper.cpp -Iminhook_1.3.3/include -std=c++20 -o winhttp_tapper.o -O0
	$CPPC -g -fPIC -c logging.cpp -std=c++20 -o logging.o
	$CPPC -g -shared -o winhttp_tapper_${arch}.asi winhttp_tapper.o logging.o -Lminhook_1.3.3/bin -lntdll -Wl,-Bstatic -lpthread -l${min_hook_lib} -static-libgcc -static-libstdc++
done
