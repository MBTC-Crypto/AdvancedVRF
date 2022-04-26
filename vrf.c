#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define N 1024
#define T 16
#define LAMBDA 32
#define LOGN 10

#define HASH_LENGTH 32
#define MU_LENGTH 32
#define BUF_LENGTH (2 * HASH_LENGTH)

typedef struct 
{
	unsigned char hash[HASH_LENGTH];
} TREE_NODE;

static int fd = -1;

static int randombytes(unsigned char *x, unsigned long long xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
  
  return 0;
}

void keygen(TREE_NODE *tree, unsigned char *r)
{
	unsigned char buf[BUF_LENGTH];	
	uint16_t i, j;
	
	/* r <-- {0,1}^{\lambda} */
	randombytes(r, LAMBDA);
	
	/* x_{i,0} = H(r,i) */
	memcpy(buf, r, LAMBDA);
	for (i = 0; i < N; i++)
	{
		memcpy(buf + LAMBDA, &i, sizeof(i));
		SHA256(buf, LAMBDA + sizeof(i), tree[N + i].hash);
	}
	
	/* x_{i,j+1} = H(x_{i,j}) */
	for (i = 0; i < N; i++)
	{
		for (j = 0; j < T; j++)
		{
			memcpy(buf, tree[N + i].hash, HASH_LENGTH);
			SHA256(buf, HASH_LENGTH, tree[N + i].hash);
		}
	}
	
	/* Merkle tree 
	 * root index = 1
	 * for index i, left child is 2*i, right child is 2*i+1 
	 * for index i, its sibling is i^1, its parent is i>>1 */
	for (i = N; i >= 2; i >>= 1)
	{
		for (j = i >> 1; j < i; j++)
		{
			memcpy(buf, tree[2 * j].hash, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, tree[2 * j + 1].hash, HASH_LENGTH);
			SHA256(buf, 2 * HASH_LENGTH, tree[j].hash);
		}
	}
}

void eval(unsigned char *v, unsigned char *y, TREE_NODE *ap, const unsigned char *mu, const uint16_t i_in, const uint16_t j_in, const unsigned char *r, const TREE_NODE *tree)
{
	unsigned char buf[BUF_LENGTH];	
	uint16_t i, j;
	
	/* x_{i,0} = H(r,i) */
	memcpy(buf, r, LAMBDA);
	memcpy(buf + LAMBDA, &i_in, sizeof(i_in));
	SHA256(buf, LAMBDA + sizeof(i_in), y);
	
	/* y = H^{t-1-j}(x_{i,0}) */
	for (j = 0; j < T - 1 - j_in; j++)
	{
		memcpy(buf, y, HASH_LENGTH);
		SHA256(buf, HASH_LENGTH, y);
	}
	
	/* v = H(y,\mu) */
	memcpy(buf, y, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, mu, MU_LENGTH);
	SHA256(buf, HASH_LENGTH + MU_LENGTH, v);
	
	/* copy the hash values of siblings along the path to the root for i-th leaf (index is N+i) */
	j = 0;
	for (i = N + i_in; i > 1; i >>= 1)
	{
		memcpy(ap[j++].hash, tree[i ^ 1].hash, sizeof(TREE_NODE));
	}
}

uint16_t verify(const unsigned char *mu, const uint16_t i_in, const uint16_t j_in, const unsigned char *v, const unsigned char *y, const TREE_NODE *ap, const TREE_NODE *root)
{
	unsigned char buf[BUF_LENGTH];	
	uint16_t i, j, i_cur;
	unsigned char v_new[HASH_LENGTH];
	unsigned char root_new[HASH_LENGTH];
	
	/* H(y,\mu)*/
	memcpy(buf, y, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, mu, MU_LENGTH);
	SHA256(buf, HASH_LENGTH + MU_LENGTH, v_new);
	
	/* if v != H(y,\mu), return 0 */
	for (i = 0; i < HASH_LENGTH; i++)
	{
		if (v_new[i] != v[i])
		{
			return 0;
		}
	}
	
	/* x_{i,t}=H^{j+1}(y) */
	memcpy(root_new, y, HASH_LENGTH);
	for (j = 0; j < j_in + 1; j++)
	{
		memcpy(buf, root_new, HASH_LENGTH);
		SHA256(buf, HASH_LENGTH, root_new);
	}
	
	/* compute root' by using x_{i,t}, index i_in, and AP */
	i_cur = i_in;
	for (i = 0; i < LOGN; i++)
	{
		/* if i-th LSB of i_in is 1, then for i-th node on the path to the root, its parent has hash value H(AP || x), where x is the hash value of this node and AP is some hash value from the AuthPath i.e. this node's sibling */  
		if (i_cur & 1)
		{
			memcpy(buf, ap[i].hash, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, root_new, HASH_LENGTH);
		}
		/* otherwise, this node's parent has hash value H(x || AP) */
		else
		{
			memcpy(buf, root_new, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, ap[i].hash, HASH_LENGTH);
		}
		SHA256(buf, 2 * HASH_LENGTH, root_new);
		
		i_cur >>= 1;
	}
	
	/* if root' != pk, return 0 */
	for (i = 0; i < HASH_LENGTH; i++)
	{
		if (root_new[i] != root->hash[i])
		{
			return 0;
		}
	}
	
	return 1;
}

int main()
{
	static TREE_NODE tree[2 * N];
	unsigned char r[LAMBDA];
	uint16_t i, j;
	uint16_t i_in, j_in;
	unsigned char v[HASH_LENGTH], y[HASH_LENGTH];
	static TREE_NODE ap[LOGN];
	unsigned char mu[MU_LENGTH];
	
	memset(tree, 0, sizeof(tree));
	
	keygen(tree, r);
	
	for (i = 1; i < 2 * N; i++)
	{
		printf("%u: ", i);
		for (j = 0; j < HASH_LENGTH; j++)
		{
			printf("%02x", tree[i].hash[j]);
		}
		printf("\n");
	}
	
	srand(time(NULL));
	i_in = rand() % N;
	j_in = rand() % T;
	printf("i=%u j=%u\n", i_in, j_in);

	randombytes(mu, MU_LENGTH);
	eval(v, y, ap, mu, i_in, j_in, r, tree);	
	
	for (i = 0; i < LOGN; i++)
	{
		for (j = 0; j < HASH_LENGTH; j++)
		{
			printf("%02x", ap[i].hash[j]);
		}
		printf("\n");
	}
	
	printf("verify: %u\n", verify(mu, i_in, j_in, v, y, ap, tree + 1));
	
	return 0;
}
