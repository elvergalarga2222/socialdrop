import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Platform } from '@socialdrop/shared';
import type { AuthResult, TokenResult, PostContent, PublishResult } from '@socialdrop/shared';
import { SocialAbstract, RefreshTokenError } from '../social-abstract.js';

interface IgApiResponse {
  id?: string;
  error?: {
    message: string;
    type: string;
    code: number;
    fbtrace_id?: string;
  };
}

function isVideoUrl(url: string): boolean {
  return /\.(mp4|mov|avi|webm)(\?|$)/i.test(url);
}

@Injectable()
export class InstagramProvider extends SocialAbstract {
  private readonly logger = new Logger(InstagramProvider.name);
  platform = Platform.INSTAGRAM;
  name = 'Instagram';
  private readonly BASE_URL = 'https://graph.facebook.com/v18.0';

  constructor(private readonly config: ConfigService) { super(); }

  /**
   * Fetch and parse JSON; throw with full API error body if the response contains
   * an `error` field (Meta Graph API returns HTTP 200 even for errors sometimes).
   */
  private async igFetch(url: string, options: RequestInit = {}, step = 'request'): Promise<IgApiResponse> {
    // ── Full request log ─────────────────────────────────────────────────
    const method = (options.method ?? 'GET').toUpperCase();
    const safeBody = options.body ? String(options.body).substring(0, 500) : '(none)';
    // Strip access_token value from URL for log readability
    const safeUrl = url.replace(/access_token=[^&]+/, 'access_token=***');
    this.logger.log(
      `[Instagram] ► ${step} | ${method} ${safeUrl} | body: ${safeBody}`,
    );

    // Use raw fetch — we parse the Instagram error body ourselves.
    // throttledFetch throws ApiError on 4xx before we can read the body,
    // so we'd lose the detailed Instagram error code/message (e.g. code=190).
    const res = await fetch(url, options);
    const responseText = await res.text();

    // ── Full response log on non-2xx ─────────────────────────────────────
    if (!res.ok) {
      this.logger.error(
        `[Instagram] ✗ ${step} | HTTP ${res.status} | raw: ${responseText.slice(0, 1000)}`,
      );
      let data: IgApiResponse = {};
      try { data = JSON.parse(responseText) as IgApiResponse; } catch { /* non-JSON */ }

      if (data.error) {
        const e = data.error;
        this.logger.error(
          `[Instagram] API Error ► code=${e.code} | subcode=${(e as any).error_subcode ?? 'n/a'} | ` +
          `type=${e.type} | message="${e.message}" | fbtrace_id=${e.fbtrace_id ?? 'n/a'}`,
        );
        if (res.status === 401 || e.code === 190) {
          const hint = (e as any).error_subcode === 460
            ? 'Sesión invalidada por Meta — reconectar cuenta de Instagram'
            : `token error ${e.code}`;
          throw new RefreshTokenError(`[Instagram] ${step} ${hint}: ${e.message}`);
        }
        throw new Error(
          `[Instagram] ${step} HTTP ${res.status} code=${e.code} subcode=${(e as any).error_subcode ?? 'n/a'}: ${e.message}`,
        );
      }

      const msg = responseText.slice(0, 300);
      if (res.status === 401) throw new RefreshTokenError(`[Instagram] ${step} HTTP 401: ${msg}`);
      throw new Error(`[Instagram] ${step} HTTP ${res.status}: ${msg}`);
    }

    // ── Parse success body ───────────────────────────────────────────────
    let data: IgApiResponse;
    try {
      data = JSON.parse(responseText) as IgApiResponse;
    } catch {
      throw new Error(`[Instagram] ${step}: non-JSON response (HTTP ${res.status}): ${responseText.slice(0, 200)}`);
    }

    // Meta sometimes returns HTTP 200 with an error payload
    if (data.error) {
      const e = data.error;
      this.logger.error(
        `[Instagram] API Error (200 body) ► code=${e.code} | subcode=${(e as any).error_subcode ?? 'n/a'} | ` +
        `type=${e.type} | message="${e.message}" | fbtrace_id=${e.fbtrace_id ?? 'n/a'}`,
      );
      if (e.code === 190 || e.code === 102) {
        const hint = (e as any).error_subcode === 460
          ? 'Sesión invalidada por Meta — reconectar cuenta de Instagram'
          : `token error ${e.code}`;
        throw new RefreshTokenError(`[Instagram] ${step} ${hint}: ${e.message}`);
      }
      throw new Error(
        `[Instagram] ${step} API error code=${e.code} subcode=${(e as any).error_subcode ?? 'n/a'}: ${e.message}`,
      );
    }

    // Log full raw success body so poll fields (status_code, error_message, etc.) are visible
    this.logger.log(
      `[Instagram] ◄ ${step} | HTTP ${res.status} | body: ${responseText.slice(0, 800)}`,
    );
    return data;
  }

  generateAuthUrl(userId: string): string {
    const params = new URLSearchParams({
      client_id: this.config.get<string>('INSTAGRAM_APP_ID', ''),
      redirect_uri: this.config.get<string>('INSTAGRAM_REDIRECT_URI', ''),
      scope: 'instagram_basic,instagram_content_publish,pages_show_list',
      response_type: 'code',
      state: userId,
    });
    return `https://www.facebook.com/v18.0/dialog/oauth?${params}`;
  }

  async authenticate(code: string, userId: string): Promise<AuthResult> {
    const params = new URLSearchParams({
      client_id: this.config.get<string>('INSTAGRAM_APP_ID', ''),
      client_secret: this.config.get<string>('INSTAGRAM_APP_SECRET', ''),
      redirect_uri: this.config.get<string>('INSTAGRAM_REDIRECT_URI', ''),
      code,
    });
    const data = await this.igFetch(`${this.BASE_URL}/oauth/access_token?${params}`, { method: 'GET' }, 'short-lived token') as { access_token: string };

    const llParams = new URLSearchParams({
      grant_type: 'fb_exchange_token',
      client_id: this.config.get<string>('INSTAGRAM_APP_ID', ''),
      client_secret: this.config.get<string>('INSTAGRAM_APP_SECRET', ''),
      fb_exchange_token: data.access_token,
    });
    const llData = await this.igFetch(`${this.BASE_URL}/oauth/access_token?${llParams}`, { method: 'GET' }, 'long-lived token') as { access_token: string; expires_in?: number };

    const igAccountId = this.config.get<string>('INSTAGRAM_ACCOUNT_ID', '');
    const igData = await this.igFetch(
      `${this.BASE_URL}/${igAccountId}?fields=name,username&access_token=${llData.access_token}`,
      { method: 'GET' }, 'account info',
    ) as { id?: string; name?: string; username?: string };

    return {
      accessToken: llData.access_token,
      profileId: igAccountId,
      accountName: (igData as any).username ?? (igData as any).name ?? igAccountId,
      tokenExpiry: (llData as any).expires_in ? new Date(Date.now() + (llData as any).expires_in * 1000) : undefined,
    };
  }

  async refreshToken(token: string): Promise<TokenResult> {
    const params = new URLSearchParams({
      grant_type: 'ig_refresh_token',
      access_token: token,
    });
    const data = await this.igFetch(`${this.BASE_URL}/refresh_access_token?${params}`, { method: 'GET' }, 'refresh token') as { access_token: string; expires_in?: number };
    return {
      accessToken: (data as any).access_token,
      tokenExpiry: (data as any).expires_in ? new Date(Date.now() + (data as any).expires_in * 1000) : undefined,
    };
  }

  async post(accessToken: string, content: PostContent): Promise<PublishResult> {
    const igUserId = this.config.get<string>('INSTAGRAM_ACCOUNT_ID', '');
    this.logger.log(`[Instagram] post() igUserId=${igUserId} mediaUrls=${JSON.stringify(content.mediaUrls)} mediaType=${content.mediaType}`);

    if (!igUserId) throw new Error('[Instagram] INSTAGRAM_ACCOUNT_ID env var is not set');

    const delays = [1000, 5000, 15000];
    let lastError: Error = new Error('Unknown error');

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        let result: PublishResult;

        if (content.instagramType === 'STORY') {
          // ── Story (image or video) ───────────────────────────────────────
          if (content.mediaType === 'VIDEO' || (content.mediaUrls?.[0] && isVideoUrl(content.mediaUrls[0]))) {
            this.logger.log(`[Instagram] Attempt ${attempt + 1}: postVideoStory`);
            result = await this.postVideoStory(accessToken, igUserId, content);
          } else {
            this.logger.log(`[Instagram] Attempt ${attempt + 1}: postImageStory`);
            result = await this.postImageStory(accessToken, igUserId, content);
          }
        } else if (content.mediaType === 'VIDEO') {
          // ── Reel (default for VIDEO) ─────────────────────────────────────
          this.logger.log(`[Instagram] Attempt ${attempt + 1}: postReel`);
          result = await this.postReel(accessToken, igUserId, content);
        } else if (content.mediaUrls && content.mediaUrls.length > 1) {
          this.logger.log(`[Instagram] Attempt ${attempt + 1}: postCarousel (${content.mediaUrls.length} images)`);
          result = await this.postCarousel(accessToken, igUserId, content);
        } else if (content.mediaUrls && content.mediaUrls.length === 1) {
          this.logger.log(`[Instagram] Attempt ${attempt + 1}: postSingleImage url=${content.mediaUrls[0]}`);
          result = await this.postSingleImage(accessToken, igUserId, content);
        } else {
          throw new Error('[Instagram] No media URL provided — Instagram requires at least one media URL');
        }
        this.logger.log(`[Instagram] ✓ Published platformPostId=${result.platformPostId}`);
        return result;
      } catch (err) {
        lastError = err as Error;
        this.logger.error(`[Instagram] Attempt ${attempt + 1} failed: ${lastError.message}`);
        if (err instanceof RefreshTokenError) throw err;
        if (attempt < 2) {
          this.logger.warn(`[Instagram] Retrying in ${delays[attempt]}ms...`);
          await new Promise(r => setTimeout(r, delays[attempt]));
        }
      }
    }
    this.logger.error(`[Instagram] ✗ All attempts failed: ${lastError.message}`);
    throw lastError;
  }

  private async postSingleImage(token: string, igUserId: string, content: PostContent): Promise<PublishResult> {
    this.logger.log(`[Instagram] Step 1/2: create media container for image_url=${content.mediaUrls![0]}`);
    const containerData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          image_url: content.mediaUrls![0],
          caption: content.text,
          access_token: token,
        }),
      },
      'create image container',
    );
    this.logger.log(`[Instagram] Step 1/2 done: containerId=${containerData.id}`);

    this.logger.log(`[Instagram] Step 2/2: publish container containerId=${containerData.id}`);
    const publishData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media_publish`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          creation_id: containerData.id,
          access_token: token,
        }),
      },
      'publish image container',
    );
    return { platformPostId: publishData.id! };
  }

  private async postCarousel(token: string, igUserId: string, content: PostContent): Promise<PublishResult> {
    const childIds: string[] = [];
    for (let i = 0; i < content.mediaUrls!.length; i++) {
      this.logger.log(`[Instagram] Carousel: creating child container ${i + 1}/${content.mediaUrls!.length} url=${content.mediaUrls![i]}`);
      const data = await this.igFetch(
        `${this.BASE_URL}/${igUserId}/media`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            image_url: content.mediaUrls![i],
            is_carousel_item: true,
            access_token: token,
          }),
        },
        `carousel child ${i + 1}`,
      );
      childIds.push(data.id!);
    }

    this.logger.log(`[Instagram] Carousel: creating carousel container with children=${childIds.join(',')}`);
    const carouselData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          media_type: 'CAROUSEL_ALBUM',
          children: childIds.join(','),
          caption: content.text,
          access_token: token,
        }),
      },
      'carousel container',
    );

    this.logger.log(`[Instagram] Carousel: publishing containerId=${carouselData.id}`);
    const publishData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media_publish`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          creation_id: carouselData.id,
          access_token: token,
        }),
      },
      'publish carousel',
    );
    return { platformPostId: publishData.id! };
  }

  // ─── Stories ──────────────────────────────────────────────────────────────

  /**
   * Publish an image Story.
   * Same permissions as Posts/Reels — no extra token scope needed.
   */
  private async postImageStory(token: string, igUserId: string, content: PostContent): Promise<PublishResult> {
    const imageUrl = content.mediaUrls?.[0];
    if (!imageUrl) throw new Error('[Instagram] Story requires at least one media URL');

    this.logger.log(`[Instagram] Story image: creating container url=${imageUrl}`);
    const containerData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          image_url: imageUrl,
          media_type: 'STORIES',
          access_token: token,
        }),
      },
      'create story image container',
    );
    this.logger.log(`[Instagram] Story image: containerId=${containerData.id} — publishing...`);

    const publishData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media_publish`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ creation_id: containerData.id, access_token: token }),
      },
      'publish story image',
    );
    return { platformPostId: publishData.id! };
  }

  /**
   * Publish a video Story (same poll flow as Reels, but media_type=STORIES).
   * Max duration: 60 seconds. Recommended aspect ratio: 9:16.
   */
  private async postVideoStory(token: string, igUserId: string, content: PostContent): Promise<PublishResult> {
    const videoUrl = content.mediaUrls?.[0];
    if (!videoUrl) throw new Error('[Instagram] Video story requires at least one media URL');
    if (!videoUrl.startsWith('https://')) {
      throw new Error(`[Instagram] Story video URL must be HTTPS — got: ${videoUrl.slice(0, 80)}`);
    }

    this.logger.log(`[Instagram] Story video: creating container url=${videoUrl}`);
    const containerData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          video_url: videoUrl,
          media_type: 'STORIES',
          access_token: token,
        }),
      },
      'create story video container',
    );
    this.logger.log(`[Instagram] Story video: containerId=${containerData.id} — polling...`);

    // Poll for processing completion (same pattern as Reels)
    const pollUrl =
      `${this.BASE_URL}/${containerData.id}` +
      `?fields=status_code,status` +
      `&access_token=${token}`;

    let status = '';
    let pollAttempts = 0;
    const maxPollAttempts = 20;

    while (status !== 'FINISHED' && pollAttempts < maxPollAttempts) {
      await new Promise(r => setTimeout(r, 5000));
      pollAttempts++;

      let pollText = '';
      let pollHttpStatus = 0;
      let statusData: { status_code?: string; status?: string } = {};
      try {
        const pollRes = await fetch(pollUrl);
        pollHttpStatus = pollRes.status;
        pollText = await pollRes.text();
        this.logger.log(
          `[Instagram] Story poll ${pollAttempts}/${maxPollAttempts} HTTP ${pollHttpStatus} | raw: ${pollText.slice(0, 400)}`,
        );
        if (!pollRes.ok) {
          let errMsg = `HTTP ${pollHttpStatus}: ${pollText.slice(0, 200)}`;
          try {
            const errJson = JSON.parse(pollText);
            if (errJson.error) {
              const e = errJson.error;
              if (e.code === 190 || e.code === 102) throw new RefreshTokenError(`[Instagram] Story poll token error: ${e.message}`);
              errMsg = `code=${e.code}: ${e.message}`;
            }
          } catch (pe) { if (pe instanceof RefreshTokenError) throw pe; }
          throw new Error(`[Instagram] Story poll failed — ${errMsg}`);
        }
        statusData = JSON.parse(pollText);
      } catch (fetchErr) {
        if (fetchErr instanceof RefreshTokenError) throw fetchErr;
        throw fetchErr;
      }

      status = statusData.status_code ?? '';
      this.logger.log(`[Instagram] Story poll ${pollAttempts}: status_code="${status}"`);
      if (status === 'ERROR') {
        throw new Error('[Instagram] Story video processing failed — Instagram returned ERROR status');
      }
    }

    if (status !== 'FINISHED') throw new Error('[Instagram] Story video processing timed out');

    this.logger.log(`[Instagram] Story video: publishing containerId=${containerData.id}`);
    const publishData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media_publish`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ creation_id: containerData.id, access_token: token }),
      },
      'publish story video',
    );
    return { platformPostId: publishData.id! };
  }

  private async postReel(token: string, igUserId: string, content: PostContent): Promise<PublishResult> {
    const mediaUrl = content.mediaUrls![0];
    if (!mediaUrl.startsWith('https://')) {
      throw new Error(`[Instagram] Reel video URL must start with https:// — got: ${mediaUrl.slice(0, 80)}`);
    }
    this.logger.log(`[Instagram] Reel: creating container for video_url=${mediaUrl}`);
    const containerData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          media_type: 'REELS',
          video_url: content.mediaUrls![0],
          caption: content.text,
          share_to_feed: true,
          access_token: token,
        }),
      },
      'create reel container',
    );
    this.logger.log(`[Instagram] Reel: containerId=${containerData.id} — polling status...`);

    let status = '';
    let pollAttempts = 0;
    const maxPollAttempts = 20;
    // error_message is NOT a valid field for media containers (causes API error 100)
    const pollUrl =
      `${this.BASE_URL}/${containerData.id}` +
      `?fields=status_code,status` +
      `&access_token=${token}`;

    while (status !== 'FINISHED' && pollAttempts < maxPollAttempts) {
      await new Promise(r => setTimeout(r, 5000));
      pollAttempts++;

      // Raw fetch so we always see the full response body, even on 4xx
      let pollText = '';
      let pollHttpStatus = 0;
      let statusData: { status_code?: string; status?: string } = {};
      try {
        const pollRes = await fetch(pollUrl);
        pollHttpStatus = pollRes.status;
        pollText = await pollRes.text();
        this.logger.log(
          `[Instagram] Poll ${pollAttempts}/${maxPollAttempts} ` +
          `HTTP ${pollHttpStatus} | raw: ${pollText.slice(0, 800)}`,
        );
        if (!pollRes.ok) {
          // Parse for structured error if possible
          let errMsg = `HTTP ${pollHttpStatus}: ${pollText.slice(0, 300)}`;
          try {
            const errJson = JSON.parse(pollText);
            if (errJson.error) {
              const e = errJson.error;
              this.logger.error(
                `[Instagram] Poll error ► code=${e.code} | subcode=${e.error_subcode ?? 'n/a'} | ` +
                `type=${e.type} | message="${e.message}" | fbtrace_id=${e.fbtrace_id ?? 'n/a'}`,
              );
              errMsg = `code=${e.code} subcode=${e.error_subcode ?? 'n/a'}: ${e.message}`;
              if (e.code === 190 || e.code === 102) throw new RefreshTokenError(`[Instagram] Poll token error: ${errMsg}`);
            }
          } catch (parseErr) { if (parseErr instanceof RefreshTokenError) throw parseErr; }
          throw new Error(`[Instagram] Poll failed — ${errMsg}`);
        }
        statusData = JSON.parse(pollText);
      } catch (fetchErr) {
        if (fetchErr instanceof RefreshTokenError) throw fetchErr;
        this.logger.error(`[Instagram] Poll ${pollAttempts} fetch threw: ${(fetchErr as Error).message}`);
        throw fetchErr;
      }

      status = statusData.status_code ?? '';
      this.logger.log(
        `[Instagram] Poll ${pollAttempts} parsed: status_code="${status}" | status="${statusData.status ?? 'n/a'}"`,
      );

      if (status === 'ERROR') {
        throw new Error(`[Instagram] Reel processing failed — Instagram returned ERROR status (no further detail available)`);
      }
    }

    if (status !== 'FINISHED') throw new Error('[Instagram] Reel processing timed out after 100s');

    this.logger.log(`[Instagram] Reel: publishing containerId=${containerData.id}`);
    const publishData = await this.igFetch(
      `${this.BASE_URL}/${igUserId}/media_publish`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          creation_id: containerData.id,
          access_token: token,
        }),
      },
      'publish reel',
    );
    return { platformPostId: publishData.id! };
  }
}
