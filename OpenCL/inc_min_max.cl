/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#define SHA1_MIN_MASK 0xffff0000
#define SHA1_MAX_MASK 0xffff0000
#define SHA1_MIN_BIT  33
#define SHA1_MAX_BIT  128
#define SHA1_MIN_SUMH 90
#define SHA1_MAX_SUMH 511
#define SHA1_MIN_SUM  380
#define SHA1_MAX_SUM  4737

// vliw1

#if VECT_SIZE == 1

#define COMPARE_MIN_MAX(h0,h1,h_bitc,h_sum,h_sumh)                                                          \
{                                                                                                           \
  if ((((h0) == 0) && (((h1) & SHA1_MIN_MASK) == 0)) || (((h0) == 0xffffffff) && (((h1) & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc) < SHA1_MIN_BIT) || ((h_bitc) > SHA1_MAX_BIT) || ((h_sum) < SHA1_MIN_SUM) || ((h_sum) > SHA1_MAX_SUM) || ((h_sumh) < SHA1_MIN_SUMH) || ((h_sumh) > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)                                                    \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos);                       \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw2

#define vector_accessible(p,c,e) (((p) + (e)) < (c))

#if VECT_SIZE == 2

#define COMPARE_MIN_MAX(h0,h1,h_bitc,h_sum,h_sumh)                                                          \
{                                                                                                           \
  if ((((h0).s0 == 0) && (((h1).s0 & SHA1_MIN_MASK) == 0)) || (((h0).s0 == 0xffffffff) && (((h1).s0 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s0 < SHA1_MIN_BIT) || ((h_bitc).s0 > SHA1_MAX_BIT) || ((h_sum).s0 < SHA1_MIN_SUM) || ((h_sum).s0 > SHA1_MAX_SUM) || ((h_sumh).s0 < SHA1_MIN_SUMH) || ((h_sumh).s0 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 0) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 0);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s1 == 0) && (((h1).s1 & SHA1_MIN_MASK) == 0)) || (((h0).s1 == 0xffffffff) && (((h1).s1 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s1 < SHA1_MIN_BIT) || ((h_bitc).s1 > SHA1_MAX_BIT) || ((h_sum).s1 < SHA1_MIN_SUM) || ((h_sum).s1 > SHA1_MAX_SUM) || ((h_sumh).s1 < SHA1_MIN_SUMH) || ((h_sumh).s1 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 1) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 1);                   \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw4

#if VECT_SIZE == 4

#define COMPARE_MIN_MAX(h0,h1,h_bitc,h_sum,h_sumh)                                                          \
{                                                                                                           \
  if ((((h0).s0 == 0) && (((h1).s0 & SHA1_MIN_MASK) == 0)) || (((h0).s0 == 0xffffffff) && (((h1).s0 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s0 < SHA1_MIN_BIT) || ((h_bitc).s0 > SHA1_MAX_BIT) || ((h_sum).s0 < SHA1_MIN_SUM) || ((h_sum).s0 > SHA1_MAX_SUM) || ((h_sumh).s0 < SHA1_MIN_SUMH) || ((h_sumh).s0 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 0) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 0);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s1 == 0) && (((h1).s1 & SHA1_MIN_MASK) == 0)) || (((h0).s1 == 0xffffffff) && (((h1).s1 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s1 < SHA1_MIN_BIT) || ((h_bitc).s1 > SHA1_MAX_BIT) || ((h_sum).s1 < SHA1_MIN_SUM) || ((h_sum).s1 > SHA1_MAX_SUM) || ((h_sumh).s1 < SHA1_MIN_SUMH) || ((h_sumh).s1 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 1) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 1);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s2 == 0) && (((h1).s2 & SHA1_MIN_MASK) == 0)) || (((h0).s2 == 0xffffffff) && (((h1).s2 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s2 < SHA1_MIN_BIT) || ((h_bitc).s2 > SHA1_MAX_BIT) || ((h_sum).s2 < SHA1_MIN_SUM) || ((h_sum).s2 > SHA1_MAX_SUM) || ((h_sumh).s2 < SHA1_MIN_SUMH) || ((h_sumh).s2 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 2) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 2);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s3 == 0) && (((h1).s3 & SHA1_MIN_MASK) == 0)) || (((h0).s3 == 0xffffffff) && (((h1).s3 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s3 < SHA1_MIN_BIT) || ((h_bitc).s3 > SHA1_MAX_BIT) || ((h_sum).s3 < SHA1_MIN_SUM) || ((h_sum).s3 > SHA1_MAX_SUM) || ((h_sumh).s3 < SHA1_MIN_SUMH) || ((h_sumh).s3 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 3) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 3);                   \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw8

#if VECT_SIZE == 8

#define COMPARE_MIN_MAX(h0,h1,h_bitc,h_sum,h_sumh)                                                          \
{                                                                                                           \
  if ((((h0).s0 == 0) && (((h1).s0 & SHA1_MIN_MASK) == 0)) || (((h0).s0 == 0xffffffff) && (((h1).s0 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s0 < SHA1_MIN_BIT) || ((h_bitc).s0 > SHA1_MAX_BIT) || ((h_sum).s0 < SHA1_MIN_SUM) || ((h_sum).s0 > SHA1_MAX_SUM) || ((h_sumh).s0 < SHA1_MIN_SUMH) || ((h_sumh).s0 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 0) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 0);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s1 == 0) && (((h1).s1 & SHA1_MIN_MASK) == 0)) || (((h0).s1 == 0xffffffff) && (((h1).s1 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s1 < SHA1_MIN_BIT) || ((h_bitc).s1 > SHA1_MAX_BIT) || ((h_sum).s1 < SHA1_MIN_SUM) || ((h_sum).s1 > SHA1_MAX_SUM) || ((h_sumh).s1 < SHA1_MIN_SUMH) || ((h_sumh).s1 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 1) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 1);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s2 == 0) && (((h1).s2 & SHA1_MIN_MASK) == 0)) || (((h0).s2 == 0xffffffff) && (((h1).s2 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s2 < SHA1_MIN_BIT) || ((h_bitc).s2 > SHA1_MAX_BIT) || ((h_sum).s2 < SHA1_MIN_SUM) || ((h_sum).s2 > SHA1_MAX_SUM) || ((h_sumh).s2 < SHA1_MIN_SUMH) || ((h_sumh).s2 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 2) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 2);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s3 == 0) && (((h1).s3 & SHA1_MIN_MASK) == 0)) || (((h0).s3 == 0xffffffff) && (((h1).s3 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s3 < SHA1_MIN_BIT) || ((h_bitc).s3 > SHA1_MAX_BIT) || ((h_sum).s3 < SHA1_MIN_SUM) || ((h_sum).s3 > SHA1_MAX_SUM) || ((h_sumh).s3 < SHA1_MIN_SUMH) || ((h_sumh).s3 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 3) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 3);                   \
    }                                                                                                       \
  }                                                                                                         \
  if ((((h0).s4 == 0) && (((h1).s4 & SHA1_MIN_MASK) == 0)) || (((h0).s4 == 0xffffffff) && (((h1).s4 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s4 < SHA1_MIN_BIT) || ((h_bitc).s4 > SHA1_MAX_BIT) || ((h_sum).s4 < SHA1_MIN_SUM) || ((h_sum).s4 > SHA1_MAX_SUM) || ((h_sumh).s4 < SHA1_MIN_SUMH) || ((h_sumh).s4 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 4) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 4);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s5 == 0) && (((h1).s5 & SHA1_MIN_MASK) == 0)) || (((h0).s5 == 0xffffffff) && (((h1).s5 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s5 < SHA1_MIN_BIT) || ((h_bitc).s5 > SHA1_MAX_BIT) || ((h_sum).s5 < SHA1_MIN_SUM) || ((h_sum).s5 > SHA1_MAX_SUM) || ((h_sumh).s5 < SHA1_MIN_SUMH) || ((h_sumh).s5 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 5) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 5);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s6 == 0) && (((h1).s6 & SHA1_MIN_MASK) == 0)) || (((h0).s6 == 0xffffffff) && (((h1).s6 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s6 < SHA1_MIN_BIT) || ((h_bitc).s6 > SHA1_MAX_BIT) || ((h_sum).s6 < SHA1_MIN_SUM) || ((h_sum).s6 > SHA1_MAX_SUM) || ((h_sumh).s6 < SHA1_MIN_SUMH) || ((h_sumh).s6 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 6) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 6);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s7 == 0) && (((h1).s7 & SHA1_MIN_MASK) == 0)) || (((h0).s7 == 0xffffffff) && (((h1).s7 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s7 < SHA1_MIN_BIT) || ((h_bitc).s7 > SHA1_MAX_BIT) || ((h_sum).s7 < SHA1_MIN_SUM) || ((h_sum).s7 > SHA1_MAX_SUM) || ((h_sumh).s7 < SHA1_MIN_SUMH) || ((h_sumh).s7 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 7) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 7);                   \
    }                                                                                                       \
  }                                                                                                         \
}

#endif

// vliw16

#if VECT_SIZE == 16

#define COMPARE_MIN_MAX(h0,h1,h_bitc,h_sum,h_sumh)                                                          \
{                                                                                                           \
  if ((((h0).s0 == 0) && (((h1).s0 & SHA1_MIN_MASK) == 0)) || (((h0).s0 == 0xffffffff) && (((h1).s0 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s0 < SHA1_MIN_BIT) || ((h_bitc).s0 > SHA1_MAX_BIT) || ((h_sum).s0 < SHA1_MIN_SUM) || ((h_sum).s0 > SHA1_MAX_SUM) || ((h_sumh).s0 < SHA1_MIN_SUMH) || ((h_sumh).s0 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 0) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 0);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s1 == 0) && (((h1).s1 & SHA1_MIN_MASK) == 0)) || (((h0).s1 == 0xffffffff) && (((h1).s1 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s1 < SHA1_MIN_BIT) || ((h_bitc).s1 > SHA1_MAX_BIT) || ((h_sum).s1 < SHA1_MIN_SUM) || ((h_sum).s1 > SHA1_MAX_SUM) || ((h_sumh).s1 < SHA1_MIN_SUMH) || ((h_sumh).s1 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 1) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 1);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s2 == 0) && (((h1).s2 & SHA1_MIN_MASK) == 0)) || (((h0).s2 == 0xffffffff) && (((h1).s2 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s2 < SHA1_MIN_BIT) || ((h_bitc).s2 > SHA1_MAX_BIT) || ((h_sum).s2 < SHA1_MIN_SUM) || ((h_sum).s2 > SHA1_MAX_SUM) || ((h_sumh).s2 < SHA1_MIN_SUMH) || ((h_sumh).s2 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 2) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 2);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s3 == 0) && (((h1).s3 & SHA1_MIN_MASK) == 0)) || (((h0).s3 == 0xffffffff) && (((h1).s3 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s3 < SHA1_MIN_BIT) || ((h_bitc).s3 > SHA1_MAX_BIT) || ((h_sum).s3 < SHA1_MIN_SUM) || ((h_sum).s3 > SHA1_MAX_SUM) || ((h_sumh).s3 < SHA1_MIN_SUMH) || ((h_sumh).s3 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 3) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 3);                   \
    }                                                                                                       \
  }                                                                                                         \
  if ((((h0).s4 == 0) && (((h1).s4 & SHA1_MIN_MASK) == 0)) || (((h0).s4 == 0xffffffff) && (((h1).s4 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s4 < SHA1_MIN_BIT) || ((h_bitc).s4 > SHA1_MAX_BIT) || ((h_sum).s4 < SHA1_MIN_SUM) || ((h_sum).s4 > SHA1_MAX_SUM) || ((h_sumh).s4 < SHA1_MIN_SUMH) || ((h_sumh).s4 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 4) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 4);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s5 == 0) && (((h1).s5 & SHA1_MIN_MASK) == 0)) || (((h0).s5 == 0xffffffff) && (((h1).s5 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s5 < SHA1_MIN_BIT) || ((h_bitc).s5 > SHA1_MAX_BIT) || ((h_sum).s5 < SHA1_MIN_SUM) || ((h_sum).s5 > SHA1_MAX_SUM) || ((h_sumh).s5 < SHA1_MIN_SUMH) || ((h_sumh).s5 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 5) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 5);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s6 == 0) && (((h1).s6 & SHA1_MIN_MASK) == 0)) || (((h0).s6 == 0xffffffff) && (((h1).s6 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s6 < SHA1_MIN_BIT) || ((h_bitc).s6 > SHA1_MAX_BIT) || ((h_sum).s6 < SHA1_MIN_SUM) || ((h_sum).s6 > SHA1_MAX_SUM) || ((h_sumh).s6 < SHA1_MIN_SUMH) || ((h_sumh).s6 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 6) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 6);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s7 == 0) && (((h1).s7 & SHA1_MIN_MASK) == 0)) || (((h0).s7 == 0xffffffff) && (((h1).s7 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s7 < SHA1_MIN_BIT) || ((h_bitc).s7 > SHA1_MAX_BIT) || ((h_sum).s7 < SHA1_MIN_SUM) || ((h_sum).s7 > SHA1_MAX_SUM) || ((h_sumh).s7 < SHA1_MIN_SUMH) || ((h_sumh).s7 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 7) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 7);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s8 == 0) && (((h1).s8 & SHA1_MIN_MASK) == 0)) || (((h0).s8 == 0xffffffff) && (((h1).s8 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s8 < SHA1_MIN_BIT) || ((h_bitc).s8 > SHA1_MAX_BIT) || ((h_sum).s8 < SHA1_MIN_SUM) || ((h_sum).s8 > SHA1_MAX_SUM) || ((h_sumh).s8 < SHA1_MIN_SUMH) || ((h_sumh).s8 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 8) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 8);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).s9 == 0) && (((h1).s9 & SHA1_MIN_MASK) == 0)) || (((h0).s9 == 0xffffffff) && (((h1).s9 & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).s9 < SHA1_MIN_BIT) || ((h_bitc).s9 > SHA1_MAX_BIT) || ((h_sum).s9 < SHA1_MIN_SUM) || ((h_sum).s9 > SHA1_MAX_SUM) || ((h_sumh).s9 < SHA1_MIN_SUMH) || ((h_sumh).s9 > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 9) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))         \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 9);                   \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).sa == 0) && (((h1).sa & SHA1_MIN_MASK) == 0)) || (((h0).sa == 0xffffffff) && (((h1).sa & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).sa < SHA1_MIN_BIT) || ((h_bitc).sa > SHA1_MAX_BIT) || ((h_sum).sa < SHA1_MIN_SUM) || ((h_sum).sa > SHA1_MAX_SUM) || ((h_sumh).sa < SHA1_MIN_SUMH) || ((h_sumh).sa > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 10) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))        \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 10);                  \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).sb == 0) && (((h1).sb & SHA1_MIN_MASK) == 0)) || (((h0).sb == 0xffffffff) && (((h1).sb & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).sb < SHA1_MIN_BIT) || ((h_bitc).sb > SHA1_MAX_BIT) || ((h_sum).sb < SHA1_MIN_SUM) || ((h_sum).sb > SHA1_MAX_SUM) || ((h_sumh).sb < SHA1_MIN_SUMH) || ((h_sumh).sb > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 11) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))        \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 11);                  \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).sc == 0) && (((h1).sc & SHA1_MIN_MASK) == 0)) || (((h0).sc == 0xffffffff) && (((h1).sc & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).sc < SHA1_MIN_BIT) || ((h_bitc).sc > SHA1_MAX_BIT) || ((h_sum).sc < SHA1_MIN_SUM) || ((h_sum).sc > SHA1_MAX_SUM) || ((h_sumh).sc < SHA1_MIN_SUMH) || ((h_sumh).sc > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 12) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))        \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 12);                  \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).sd == 0) && (((h1).sd & SHA1_MIN_MASK) == 0)) || (((h0).sd == 0xffffffff) && (((h1).sd & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).sd < SHA1_MIN_BIT) || ((h_bitc).sd > SHA1_MAX_BIT) || ((h_sum).sd < SHA1_MIN_SUM) || ((h_sum).sd > SHA1_MAX_SUM) || ((h_sumh).sd < SHA1_MIN_SUMH) || ((h_sumh).sd > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 13) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))        \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 13);                  \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).se == 0) && (((h1).se & SHA1_MIN_MASK) == 0)) || (((h0).se == 0xffffffff) && (((h1).se & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).se < SHA1_MIN_BIT) || ((h_bitc).se > SHA1_MAX_BIT) || ((h_sum).se < SHA1_MIN_SUM) || ((h_sum).se > SHA1_MAX_SUM) || ((h_sumh).se < SHA1_MIN_SUMH) || ((h_sumh).se > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 14) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))        \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 14);                  \
    }                                                                                                       \
  }                                                                                                         \
                                                                                                            \
  if ((((h0).sf == 0) && (((h1).sf & SHA1_MIN_MASK) == 0)) || (((h0).sf == 0xffffffff) && (((h1).sf & SHA1_MAX_MASK) == SHA1_MAX_MASK ))  || ((h_bitc).sf < SHA1_MIN_BIT) || ((h_bitc).sf > SHA1_MAX_BIT) || ((h_sum).sf < SHA1_MIN_SUM) || ((h_sum).sf > SHA1_MAX_SUM) || ((h_sumh).sf < SHA1_MIN_SUMH) || ((h_sumh).sf > SHA1_MAX_SUMH))  \
  {                                                                                                         \
    const u32 final_hash_pos = digests_offset + 0;                                                          \
                                                                                                            \
    if (vector_accessible (il_pos, il_cnt, 15) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))        \
    {                                                                                                       \
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, final_hash_pos, gid, il_pos + 15);                  \
    }                                                                                                       \
  }                                                                                                         \
}

#endif
