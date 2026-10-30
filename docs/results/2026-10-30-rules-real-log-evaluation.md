# Rules evaluation on public real logs — 2026-10-30

## Scope

This measures revision 2 of `log-format-rules` on real log lines from the public
[LogHub](https://github.com/logpai/loghub) 2k samples. It is a small, single-rater
measurement, not a production accuracy claim. The logs and labels stay outside
this repository, which accepts synthetic data only.

**Attention** means a line labelled `security_event`, `error`, or `warning`.
Precision and recall below are for attention lines; an abstained prediction does
not count as flagged.

## Method

1. Rules were developed on the Linux and OpenSSH samples and the synthetic
   fixtures only.
2. Holdout lines were sampled, one per log template, with a fixed seed.
3. The author labelled each holdout line from its text before seeing predictions.
4. Each holdout was scored once.

The first holdout exposed a design fault: explicit `[error]` lines abstained when
the subsystem was unknown. Fixing that made the first holdout unusable as
evidence, so a second one was drawn from datasets not used until then. No rule was
changed in response to the second holdout's results.

## Results

| Sample | Lines | Coverage | Precision | Recall | Subsystem | Five-class severity | False security events |
|---|---:|---:|---:|---:|---:|---:|---:|
| Holdout 1, frozen rules (Thunderbird, Zookeeper, OpenStack, Apache, HDFS, Spark) | 160 | 31% | 9/9 | 9/21 (43%) | 90% | 96% | 0 |
| Holdout 1 after the fix — **contaminated** | 160 | 85% | 16/16 | 16/21 (76%) | 92% | 98% | 0 |
| **Holdout 2, fresh (Hadoop, Mac, Proxifier, Android, BGL)** | **104** | **72%** | **20/22 (91%)** | **20/29 (69%)** | **92%** | **88%** | **0** |

Subsystem and five-class accuracy cover answered lines only. Holdout 2 is the
number to quote.

## Known limits

- **Security recall is not measured on a holdout.** Neither sample contained a
  labelled security event; they show the absence of false alarms. Security
  detection is exercised on the development data, where the rules flagged 658 of
  1,999 Linux lines and 1,489 of 1,999 OpenSSH lines.
- Android abstained on 23 of 24 lines: its single-letter levels are not parsed.
- BGL's `INFO` level hides lines a person would treat as warnings, because an
  explicit level is trusted.
- Bare application text with no program, level, or known vocabulary abstains.
- Labels come from one rater, who also wrote the rules.

## Local sanity check

On 429 lines of a live Debian host journal, the rules flagged 18 lines in four
patterns (a failing service unit and SSH read errors), all genuine on review, and
no security event. Missed events were not assessed. This run found that modern
`sshd-session` lines were unrecognized, which was then fixed.

Throughput was 25,000–49,000 lines per second on one CPU core of the development
machine.
