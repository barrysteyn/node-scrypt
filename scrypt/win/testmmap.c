
#include <windows.h>
#include <errno.h>
#include <io.h>

#include "sys/mman.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifndef NULL
#define NULL    (void*)0
#endif

/* Modes borrowed from http://stackoverflow.com/a/593017 */
typedef int mode_t;
static const mode_t S_IRUSR      = (mode_t) _S_IREAD;     //* < read by user */
static const mode_t S_IWUSR      = (mode_t) _S_IWRITE;    //* < write by user */

const char* map_file_name = "map_file.dat";

int test_anon_map_readwrite()
{
    int result = 0;
    void* map = mmap(NULL, 1024, PROT_READ | PROT_WRITE,
 		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap (MAP_ANONYMOUS, PROT_READ | PROT_WRITE) returned unexpected error: %d\n", errno);
        return -1;
    }

    *((unsigned char*)map) = 1;

    result = munmap(map, 1024);

    if (result != 0)
        printf("munmap (MAP_ANONYMOUS, PROT_READ | PROT_WRITE) returned unexpected error: %d\n", errno);

    return result;
}

int test_anon_map_readonly()
{
    int result = 0;
    void* map = mmap(NULL, 1024, PROT_READ,
 		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap (MAP_ANONYMOUS, PROT_READ) returned unexpected error: %d\n", errno);
        return -1;
    }

    *((unsigned char*)map) = 1;

    result = munmap(map, 1024);

    if (result != 0)
        printf("munmap (MAP_ANONYMOUS, PROT_READ) returned unexpected error: %d\n", errno);

    return result;
}

int test_anon_map_writeonly()
{
    int result = 0;
    void* map = mmap(NULL, 1024, PROT_WRITE,
 		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap (MAP_ANONYMOUS, PROT_WRITE) returned unexpected error: %d\n", errno);
        return -1;
    }

    *((unsigned char*)map) = 1;

    result = munmap(map, 1024);

    if (result != 0)
        printf("munmap (MAP_ANONYMOUS, PROT_WRITE) returned unexpected error: %d\n", errno);

    return result;
}

int test_anon_map_readonly_nowrite()
{
    int result = 0;
    void* map = mmap(NULL, 1024, PROT_READ,
 		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap (MAP_ANONYMOUS, PROT_READ) returned unexpected error: %d\n", errno);
        return -1;
    }

    if (*((unsigned char*)map) != 0)
        printf("test_anon_map_readonly_nowrite (MAP_ANONYMOUS, PROT_READ) returned unexpected value: %d\n",
                (int)*((unsigned char*)map));

    result = munmap(map, 1024);

    if (result != 0)
        printf("munmap (MAP_ANONYMOUS, PROT_READ) returned unexpected error: %d\n", errno);

    return result;
}

int test_file_map_readwrite()
{
    int result = 0;
    mode_t mode = S_IRUSR | S_IWUSR;
    int o = open(map_file_name, O_TRUNC | O_BINARY | O_RDWR | O_CREAT, mode);

    void* map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, o, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap returned unexpected error: %d\n", errno);
        return -1;
    }

    *((unsigned char*)map) = 1;

    result = munmap(map, 1024);

    if (result != 0)
        printf("munmap returned unexpected error: %d\n", errno);

    close(o);

    /*TODO: get file info and content and compare it with the sources conditions */
    unlink(map_file_name);

    return result;
}

int test_file_map_mlock_munlock()
{
    const size_t map_size = 1024;

    int result = 0;
    mode_t mode = S_IRUSR | S_IWUSR;
    void * map = 0;

    int o = open(map_file_name, O_TRUNC | O_BINARY | O_RDWR | O_CREAT, mode);
    if (o == -1)
    {
        printf("unable to create file %s: %d\n", map_file_name, errno);
        return -1;
    }

    map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, o, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap returned unexpected error: %d\n", errno);
        result = -1;
        goto done_close;
    }

    if (mlock(map, map_size) != 0)
    {
        printf("mlock returned unexpected error: %d\n", errno);
        result = -1;
        goto done_munmap;
    }

    *((unsigned char*)map) = 1;

    if (munlock(map, map_size) != 0)
    {
        printf("munlock returned unexpected error: %d\n", errno);
        result = -1;
    }

done_munmap:
    result = munmap(map, map_size);

    if (result != 0)
        printf("munmap returned unexpected error: %d\n", errno);

done_close:
    close(o);

    unlink(map_file_name);
done:
    return result;
}

int test_file_map_msync()
{
    const size_t map_size = 1024;
    void * map = 0;
    int result = 0;
    mode_t mode = S_IRUSR | S_IWUSR;
    int o = open(map_file_name, O_TRUNC | O_BINARY | O_RDWR | O_CREAT, mode);
    if (o == -1)
    {
        printf("unable to create file %s: %d\n", map_file_name, errno);
        return -1;
    }

    map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, o, 0);
    if (map == MAP_FAILED)
    {
        printf("mmap returned unexpected error: %d\n", errno);
        result = -1;
        goto done_close;
    }

    *((unsigned char*)map) = 1;

    if (msync(map, map_size, MS_SYNC) != 0)
    {
        printf("msync returned unexpected error: %d\n", errno);
        result = -1;
    }

    result = munmap(map, map_size);

    if (result != 0)
        printf("munmap returned unexpected error: %d\n", errno);

done_close:
    close(o);

    unlink(map_file_name);
done:
    return result;
}

#define EXEC_TEST(name) \
    if (name() != 0) { result = -1; printf( #name ": fail\n"); } \
    else { printf(#name ": pass\n"); }

int main()
{
    int result = 0;

    EXEC_TEST(test_anon_map_readwrite);
    //NOTE: this test must cause an access violation exception
    //EXEC_TEST(test_anon_map_readonly);
    EXEC_TEST(test_anon_map_readonly_nowrite);
    EXEC_TEST(test_anon_map_writeonly);

    EXEC_TEST(test_file_map_readwrite);
    EXEC_TEST(test_file_map_mlock_munlock);
    EXEC_TEST(test_file_map_msync);
    //TODO: EXEC_TEST(test_file_map_mprotect);

    return result;
}
