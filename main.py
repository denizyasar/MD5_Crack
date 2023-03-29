import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import hashlib
import threading

# CUDA kernel to calculate MD5 hash of a string
md5_kernel = """
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

extern "C" {
    __global__ void md5_cuda(char* str, unsigned char* md5_hash) {
        MD5_CTX md5_ctx;
        MD5_Init(&md5_ctx);
        MD5_Update(&md5_ctx, str, strlen(str));
        MD5_Final(md5_hash, &md5_ctx);
    }
}
"""

# Compile CUDA kernel
md5_module = SourceModule(md5_kernel)

# Function to calculate MD5 hash of a string using CUDA
def md5_string_cuda(string):
    md5_cuda = md5_module.get_function("md5_cuda")
    md5_hash = bytearray(hashlib.md5().digest_size)
    md5_cuda(cuda.In(string.encode()), cuda.Out(md5_hash), block=(1,1,1), grid=(1,1))
    return md5_hash.hex()

# Generator function to yield strings one by one
def string_generator(strings):
    for string in strings:
        yield string

# Function to find the MD5 hash of multiple strings using multithreading
def find_md5_multithread(strings):
    threads = []
    for string in string_generator(strings):
        t = threading.Thread(target=find_md5, args=(string,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# Function to print the MD5 hash of a string
def find_md5(string):
    md5 = md5_string_cuda(string)
    print(f"The MD5 hash of '{string}' is {md5}")

# Example usage
if __name__ == '__main__':
    strings = ['hello world', 'pycuda is awesome', 'cuda is fast', 'md5 hash']
    find_md5_multithread(strings)
