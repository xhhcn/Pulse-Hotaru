/**
 * ISO 3166-1 → 简体中文（官方全称），数据来自 `i18n-iso-countries` 的 zh 语言包，
 * 覆盖其收录的所有国家/地区代码。用于将 Pulse 的 location 字段（常见为二位码或英文国名）
 * 显示为中文。
 */
import countries from 'i18n-iso-countries';
import en from 'i18n-iso-countries/langs/en.json';
import zh from 'i18n-iso-countries/langs/zh.json';

countries.registerLocale(en);
countries.registerLocale(zh);

/** 常见非 ISO 管理口径的别名 → alpha-2 */
const CODE_ALIASES: Record<string, string> = {
  UK: 'GB',
  EN: 'GB',
  EL: 'GR', // EU 部分场景用 EL 表示希腊
};

/**
 * 将 Pulse `location` 原始字符串解析为简体中文国家/地区名。
 * - 支持 ISO 3166-1 alpha-2 / alpha-3
 * - 支持英文官方国名（与 i18n-iso-countries 英文条目一致）
 * - 无法解析时返回原串，避免丢失管理员自定义值（如「内网」）
 */
export function locationToZh(raw: string | null | undefined): string {
  if (raw == null) return '';
  const s = String(raw).trim();
  if (s === '') return '';

  const upper = s.toUpperCase();

  // 两位码（含 UK 等别名）
  if (/^[A-Z]{2}$/.test(upper)) {
    const code = CODE_ALIASES[upper] ?? upper;
    const name = countries.getName(code, 'zh', { select: 'official' });
    if (name) return name;
  }

  // 三位码
  if (/^[A-Z]{3}$/.test(upper)) {
    const a2 = countries.alpha3ToAlpha2(upper);
    if (a2) {
      const name = countries.getName(a2, 'zh', { select: 'official' });
      if (name) return name;
    }
  }

  // 长串里嵌入的二字码，如 "US-East"
  const word2 = upper.match(/\b([A-Z]{2})\b/);
  if (word2) {
    const code = CODE_ALIASES[word2[1]] ?? word2[1];
    const name = countries.getName(code, 'zh', { select: 'official' });
    if (name) return name;
  }

  // 英文国名
  const fromEn = countries.getAlpha2Code(s, 'en');
  if (fromEn) {
    const name = countries.getName(fromEn, 'zh', { select: 'official' });
    if (name) return name;
  }

  // 中文国名本身（已是正式名称则直接通过 getName 校验）
  const fromZh = countries.getAlpha2Code(s, 'zh');
  if (fromZh) {
    const name = countries.getName(fromZh, 'zh', { select: 'official' });
    if (name) return name;
  }

  return s;
}
