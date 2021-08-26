/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#endif

typedef struct wd
{
  u32 data_buf[104];
} wd_t;

typedef struct wd_tmp
{
  u32 dgst[8];
} wd_tmp_t;

KERNEL_FQ void m57440_init (KERN_ATTR_TMPS_ESALT (wd_tmp_t, wd_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w[8];

  w[0] = 0x2e434457; // "WDC."
  w[1] = pws[gid].i[0];
  w[2] = pws[gid].i[1];
  w[3] = pws[gid].i[2];
  w[4] = pws[gid].i[3];
  w[5] = pws[gid].i[4];
  w[6] = pws[gid].i[5];
  w[7] = pws[gid].i[6];

  u32 pw_salt_len = pws[gid].pw_len + 4;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_utf16le_swap (&ctx, w, pw_salt_len);

  sha256_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];
  tmps[gid].dgst[5] = ctx.h[5];
  tmps[gid].dgst[6] = ctx.h[6];
  tmps[gid].dgst[7] = ctx.h[7];

}

KERNEL_FQ void m57440_loop (KERN_ATTR_TMPS_ESALT (wd_tmp_t, wd_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 digest[16] = { 0 };

  digest[0] = tmps[gid].dgst[0];
  digest[1] = tmps[gid].dgst[1];
  digest[2] = tmps[gid].dgst[2];
  digest[3] = tmps[gid].dgst[3];
  digest[4] = tmps[gid].dgst[4];
  digest[5] = tmps[gid].dgst[5];
  digest[6] = tmps[gid].dgst[6];
  digest[7] = tmps[gid].dgst[7];

  for (u32 i = 0; i < loop_cnt; i++) {
    sha256_ctx_t ctx;
    sha256_init (&ctx);

    sha256_update (&ctx, digest, 32);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  tmps[gid].dgst[0] = digest[0];
  tmps[gid].dgst[1] = digest[1];
  tmps[gid].dgst[2] = digest[2];
  tmps[gid].dgst[3] = digest[3];
  tmps[gid].dgst[4] = digest[4];
  tmps[gid].dgst[5] = digest[5];
  tmps[gid].dgst[6] = digest[6];
  tmps[gid].dgst[7] = digest[7];

}

KERNEL_FQ void m57440_comp (KERN_ATTR_TMPS_ESALT (wd_tmp_t, wd_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];

  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  u32 kek[8];

  // reverse the KEK
  kek[0] = hc_swap32_S (tmps[gid].dgst[7]);
  kek[1] = hc_swap32_S (tmps[gid].dgst[6]);
  kek[2] = hc_swap32_S (tmps[gid].dgst[5]);
  kek[3] = hc_swap32_S (tmps[gid].dgst[4]);
  kek[4] = hc_swap32_S (tmps[gid].dgst[3]);
  kek[5] = hc_swap32_S (tmps[gid].dgst[2]);
  kek[6] = hc_swap32_S (tmps[gid].dgst[1]);
  kek[7] = hc_swap32_S (tmps[gid].dgst[0]);

  u32 ks[60];

  AES256_set_decrypt_key (ks, kek, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 pt_buf[104];

  for (u32 i = 0; i < 104; i += 4)
  {
    AES256_decrypt (ks, esalt_bufs[0].data_buf + i, pt_buf + i, s_td0, s_td1, s_td2, s_td3, s_td4);
  }

  if (pt_buf[43] == 0x314b4544) // "DEK1" reversed
  {
    const float entropy = hc_get_entropy (pt_buf, 104);

    if (entropy < 6.0f)
    {
      if (hc_atomic_inc (&hashes_shown[0]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS, digests_cnt, 0, 0, gid, 0, 0, 0);
      }
    }
  }

}
