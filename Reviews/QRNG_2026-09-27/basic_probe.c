#include <stdio.h>
#include <string.h>
#include "toeplitz.h"
#include "entropy.h"
int main(void) {
 uint32_t seed[96], x[64]={0}, y[64]={0}, a[32]={0}, b[32]={0};
 for(int i=0;i<96;i++) seed[i]=0x12345679u+i;
 toeplitz_build_lookup(seed);
 y[32]=0xdeadbeef;
 toeplitz_extractor_ultra_fast(x,64,a,32);
 toeplitz_extractor_ultra_fast(y,64,b,32);
 printf("second_half_change_ignored=%d\n",memcmp(a,b,sizeof a)==0);
 memset(a,0xA5,sizeof a);
 toeplitz_extractor_ultra_fast(x,64,a,32);
 printf("zero_input_preserves_old_output=%d\n",a[0]==0xA5A5A5A5u && a[31]==0xA5A5A5A5u);
 memset(a,0,sizeof a); memset(b,0,sizeof b); x[0]=1;
 toeplitz_extractor_ultra_fast(x,64,a,32);
 seed[50]^=0xffffffffu; toeplitz_build_lookup(seed);
 toeplitz_extractor_ultra_fast(x,64,b,32);
 printf("seed_word50_change_ignored=%d\n",memcmp(a,b,sizeof a)==0);
 printf("first_output_bit_seed_even_test=");
 seed[0]&=~1u; toeplitz_build_lookup(seed);
 int always_zero=1;
 for(int k=0;k<256;k++){ memset(a,0,sizeof a); x[0]=k; toeplitz_extractor_ultra_fast(x,64,a,32); if(a[0]&1) always_zero=0; }
 printf("%d\n",always_zero);
 uint16_t samples[1024]; entropy_context_t e; entropy_init(&e); e.raw_pool=samples;
 for(int i=0;i<1024;i++) samples[i]=i+1;
 samples[1022]=60000; samples[1023]=60000;
 entropy_reset(&e); entropy_run_health_checks(&e,1); printf("rct_boundary_first_status=%d\n",e.health_status);
 for(int i=0;i<1024;i++) samples[i]=i+1;
 samples[0]=60000;
 entropy_reset(&e); entropy_run_health_checks(&e,1); printf("rct_boundary_second_status=%d (three consecutive 60000 escaped)\n",e.health_status);
 return 0;
}
