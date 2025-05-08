import time
from memory_profiler import profile
import AESECCEAX  
import RSAECCEAX   
import ECCAESGCM   

@profile
def profile_AESECCEAX_hybrid_encryption():
    start_time = time.time()
    AESECCEAX.hybrid_encryption_demo()  
    end_time = time.time()
    print(f"AESECCEAX Total Execution Time: {end_time - start_time:.4f} seconds")

@profile
def profile_RSAEECEAX_hybrid_encryption():
    start_time = time.time()
    RSAECCEAX.hybrid_encryption_demo()  
    end_time = time.time()
    print(f"RSAEECEAX Total Execution Time: {end_time - start_time:.4f} seconds")

@profile
def profile_ECCAESGCM_hybrid_encryption():
    start_time = time.time()
    ECCAESGCM.hybrid_encryption_demo()
    end_time = time.time()
    print(f"ECCAESGCM Total Execution Time: {end_time - start_time:.4f} seconds")

if __name__ == "__main__":
    profile_AESECCEAX_hybrid_encryption()
    profile_RSAEECEAX_hybrid_encryption()
    profile_ECCAESGCM_hybrid_encryption()
