"use client";

import { useState } from "react";
import useSWR from "swr";
import { Button, Tag, Text } from "@opal/components";
import { InputVertical, Section, toast } from "@opal/layouts";
import { SvgSimpleLoader, SvgCopy } from "@opal/icons";
import {
  fetchDomainRecords,
  verifyDomainViaDns,
  type SSOLoginDomains,
  type SSOLoginDomainStatus,
} from "@/lib/sso/svc";

interface SSODomainVerificationProps {
  domains: string[];
}

function CopyRow({ label, value }: { label: string; value: string }) {
  return (
    <Section
      flexDirection="row"
      alignItems="center"
      justifyContent="between"
      height="fit"
      gap={0.5}
      padding={0.5}
      className="rounded-12 border border-border-02 bg-background-neutral-01"
    >
      <Section flexDirection="column" alignItems="stretch" height="fit" gap={0}>
        <Text font="secondary-body" color="text-03" as="span">
          {label}
        </Text>
        <Text font="main-ui-mono" color="text-04" as="span">
          {value}
        </Text>
      </Section>
      <Button
        prominence="tertiary"
        size="sm"
        icon={SvgCopy}
        onClick={() => {
          navigator.clipboard?.writeText(value);
          toast.success("Copied");
        }}
      />
    </Section>
  );
}

// Cloud only: a domain auto-provisions strangers on it, so it routes no one
// until the workspace proves it owns the domain by publishing a DNS TXT record.
// Records populate for the domains being configured, whether or not the provider
// is saved yet, so setup is one pass.
export default function SSODomainVerification({
  domains,
}: SSODomainVerificationProps) {
  const { data, mutate, isLoading } = useSWR<SSOLoginDomains>(
    domains.length > 0 ? ["sso-domain-records", ...domains] : null,
    () => fetchDomainRecords(domains)
  );
  const [busyDomain, setBusyDomain] = useState<string | null>(null);

  if (domains.length === 0) return null;

  async function verify(domain: string) {
    setBusyDomain(domain);
    try {
      await verifyDomainViaDns(domain);
      await mutate();
      toast.success(`${domain} verified`);
    } catch (exc) {
      toast.error(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusyDomain(null);
    }
  }

  function renderDomain(domain: SSOLoginDomainStatus) {
    const busy = busyDomain === domain.domain;
    return (
      <Section
        key={domain.domain}
        flexDirection="column"
        alignItems="stretch"
        height="fit"
        gap={0.5}
        padding={0.75}
        className="rounded-12 border border-border-02"
      >
        <Section
          flexDirection="row"
          justifyContent="between"
          alignItems="center"
          height="fit"
        >
          <Text font="main-ui-body" color="text-04" as="span">
            {domain.domain}
          </Text>
          {domain.verified ? (
            <Tag color="green" title="Verified" />
          ) : (
            <Tag color="amber" title="Pending" />
          )}
        </Section>

        {!domain.verified && (
          <Section
            flexDirection="column"
            alignItems="stretch"
            height="fit"
            gap={0.5}
          >
            <Text font="secondary-body" color="text-03" as="span">
              {`Add this TXT record at your DNS provider to prove you control ${domain.domain}, then verify.`}
            </Text>
            <CopyRow label="Type" value="TXT" />
            {domain.record_host && (
              <CopyRow label="Name" value={domain.record_host} />
            )}
            {domain.record_value && (
              <CopyRow label="Value" value={domain.record_value} />
            )}
            <Section flexDirection="row" justifyContent="end" height="fit">
              <Button
                onClick={() => verify(domain.domain)}
                disabled={busy}
                icon={busy ? SvgSimpleLoader : undefined}
              >
                Verify domain
              </Button>
            </Section>
          </Section>
        )}
      </Section>
    );
  }

  const rows = data?.domains ?? [];

  return (
    <InputVertical
      title="Domain verification"
      description="A domain signs your workspace's users in automatically only after you verify you own it. Add the DNS record below, then verify."
      withLabel
    >
      <Section
        flexDirection="column"
        alignItems="stretch"
        height="fit"
        gap={0.5}
      >
        {isLoading && rows.length === 0 ? (
          <Section
            flexDirection="row"
            alignItems="center"
            height="fit"
            gap={0.5}
          >
            <SvgSimpleLoader className="size-4 animate-spin text-text-03" />
            <Text font="main-ui-body" color="text-03">
              Loading…
            </Text>
          </Section>
        ) : (
          rows.map(renderDomain)
        )}
      </Section>
    </InputVertical>
  );
}
