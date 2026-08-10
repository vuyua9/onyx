"use client";

import { useState } from "react";
import useSWR from "swr";
import { Button, InputTypeIn, Tag, Text } from "@opal/components";
import { InputVertical, Section, toast } from "@opal/layouts";
import { SvgSimpleLoader } from "@opal/icons";
import InputSelect from "@/refresh-components/inputs/InputSelect";
import { SWR_KEYS } from "@/lib/swr-keys";
import {
  fetchSSOLoginDomains,
  sendDomainVerificationCode,
  verifyDomainViaEmail,
  type SSOLoginDomains,
} from "@/lib/sso/svc";

interface SSODomainVerificationProps {
  domains: string[];
}

// Cloud only: a domain auto-provisions strangers on it, so it routes no one
// until the workspace proves it owns the domain with a code to a role mailbox.
// The list self-gates: the endpoint returns nothing off cloud, so nothing renders.
export default function SSODomainVerification({
  domains,
}: SSODomainVerificationProps) {
  const { data, mutate } = useSWR<SSOLoginDomains>(
    SWR_KEYS.adminSsoDomains,
    fetchSSOLoginDomains
  );

  const [activeDomain, setActiveDomain] = useState<string | null>(null);
  const [mailboxPrefix, setMailboxPrefix] = useState("");
  const [code, setCode] = useState("");
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const prefixes = data?.mailboxPrefixes ?? [];
  const claimed = (data?.domains ?? []).filter((domain) =>
    domains.includes(domain.domain)
  );
  if (claimed.length === 0) return null;

  function openVerify(domain: string) {
    setActiveDomain(domain);
    setMailboxPrefix(prefixes[0] ?? "");
    setCode("");
    setSentTo(null);
  }

  async function sendCode(domain: string) {
    setBusy(true);
    try {
      const { recipient } = await sendDomainVerificationCode(
        domain,
        mailboxPrefix
      );
      setSentTo(recipient);
      toast.success(`Code sent to ${recipient}`);
    } catch (exc) {
      toast.error(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  async function verify(domain: string) {
    setBusy(true);
    try {
      const updated = await verifyDomainViaEmail(domain, code);
      await mutate(updated, { revalidate: false });
      setActiveDomain(null);
      toast.success(`${domain} verified`);
    } catch (exc) {
      toast.error(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  return (
    <InputVertical
      title="Domain verification"
      description="A domain signs your workspace's users in automatically only after you verify you own it."
      withLabel
    >
      <Section
        flexDirection="column"
        alignItems="stretch"
        height="fit"
        gap={0.5}
      >
        {claimed.map((domain) => (
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
                activeDomain !== domain.domain && (
                  <Button
                    prominence="secondary"
                    size="sm"
                    onClick={() => openVerify(domain.domain)}
                  >
                    Verify
                  </Button>
                )
              )}
            </Section>

            {!domain.verified && activeDomain === domain.domain && (
              <Section
                flexDirection="column"
                alignItems="stretch"
                height="fit"
                gap={0.5}
              >
                {sentTo === null ? (
                  <>
                    <InputSelect
                      value={mailboxPrefix}
                      onValueChange={setMailboxPrefix}
                    >
                      <InputSelect.Trigger placeholder="Send code to" />
                      <InputSelect.Content>
                        {prefixes.map((prefix) => (
                          <InputSelect.Item key={prefix} value={prefix}>
                            {`${prefix}@${domain.domain}`}
                          </InputSelect.Item>
                        ))}
                      </InputSelect.Content>
                    </InputSelect>
                    <Section
                      flexDirection="row"
                      justifyContent="end"
                      height="fit"
                    >
                      <Button
                        onClick={() => sendCode(domain.domain)}
                        disabled={busy || !mailboxPrefix}
                        icon={busy ? SvgSimpleLoader : undefined}
                      >
                        Send code
                      </Button>
                    </Section>
                  </>
                ) : (
                  <>
                    <InputTypeIn
                      value={code}
                      onChange={(event) => setCode(event.target.value)}
                      placeholder={`Enter the code sent to ${sentTo}`}
                    />
                    <Section
                      flexDirection="row"
                      justifyContent="end"
                      height="fit"
                    >
                      <Button
                        onClick={() => verify(domain.domain)}
                        disabled={busy || !code}
                        icon={busy ? SvgSimpleLoader : undefined}
                      >
                        Verify
                      </Button>
                    </Section>
                  </>
                )}
              </Section>
            )}
          </Section>
        ))}
      </Section>
    </InputVertical>
  );
}
