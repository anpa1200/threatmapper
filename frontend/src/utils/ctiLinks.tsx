import type { ReactNode } from 'react';

const ATTACK_ID_PATTERN = /^T\d{4}(?:\.\d{3})?$/i;
const IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;

export function isTechniqueId(value: string) {
  return ATTACK_ID_PATTERN.test(value.trim());
}

export function techniqueHref(attackId: string) {
  return `/navigator?technique=${encodeURIComponent(attackId.trim().toUpperCase())}`;
}

export function inferIocType(value: string, explicitType?: string) {
  const normalizedType = (explicitType ?? '').toLowerCase();
  const trimmed = value.trim();
  if (['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'file', 'ioc'].includes(normalizedType)) {
    return normalizedType;
  }
  if (/^https?:\/\//i.test(trimmed)) return 'url';
  if (IPV4_PATTERN.test(trimmed)) return 'ipv4';
  if (/^[a-f0-9]{32}$/i.test(trimmed)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(trimmed)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(trimmed)) return 'sha256';
  if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(trimmed)) return 'email';
  if (/^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/.test(trimmed) && !/\.(dll|exe|sys|ocx)$/i.test(trimmed)) return 'domain';
  return normalizedType || 'ioc';
}

export function iocNodeHref(value: string, explicitType?: string, source = 'AdversaryGraph') {
  const params = new URLSearchParams({
    type: inferIocType(value, explicitType),
    value: value.trim(),
    tier: '0',
    sources: source,
  });
  return `/ioc-node?${params.toString()}`;
}

export function TtpLink({
  id,
  children,
  title,
  className = 'font-mono text-mitre-accent hover:underline',
}: {
  id: string;
  children?: ReactNode;
  title?: string;
  className?: string;
}) {
  return <a href={techniqueHref(id)} title={title} className={className}>{children ?? id.toUpperCase()}</a>;
}

export function IocLink({
  value,
  type,
  source,
  children,
  className = 'break-all font-mono text-cyan-200 hover:text-cyan-100 hover:underline',
}: {
  value: string;
  type?: string;
  source?: string;
  children?: ReactNode;
  className?: string;
}) {
  return <a href={iocNodeHref(value, type, source)} className={className}>{children ?? value}</a>;
}
