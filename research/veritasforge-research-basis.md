# VeritasForge research basis

## Design decisions

VeritasForge is an evidence-intelligence platform, not a binary authenticity classifier. The C2PA standard describes cryptographically verifiable manifests whose trustworthiness is assessed through a defined trust model; it is therefore appropriate to report verified, present-but-untrusted, broken, or absent provenance rather than equating absence with falsity [1] [2].

NIST SP 800-86 presents digital forensics as a practical incident-response process and explicitly cautions that it is not an all-inclusive forensic investigation guide or legal advice. VeritasForge consequently records methods, assumptions, environment, limitations, and chain-of-custody facts rather than making legal conclusions [3].

Benchmark research shows that accessible forensic evaluation requires known ground truth and that synthetic, legally usable datasets can support reproducible evaluation. The platform should separate laboratory performance from operational robustness, track detector versions, and preserve experiment metadata [4].

Source-forensics research spans camera identification, recapture, computer-generated imagery, generated-image detection, and source-platform identification. Research findings can be useful but are sensitive to training data, post-processing, and generalization; advanced detectors must therefore be labeled EXPERIMENTAL, RESEARCH, VALIDATED, or PRODUCTION only after evidence and benchmark review [5].

## References

[1] Coalition for Content Provenance and Authenticity, “C2PA.” https://c2pa.org/
[2] C2PA, “Content Credentials Specification 2.4.” https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html
[3] NIST, “Guide to Integrating Forensic Techniques into Incident Response, SP 800-86.” https://csrc.nist.gov/pubs/sp/800/86/final
[4] João P. Cardenuto and Anderson Rocha, “Benchmarking Scientific Image Forgery Detectors.” https://arxiv.org/html/2105.12872v1
[5] Pengpeng Yang et al., “A Survey of Deep Learning-Based Source Image Forensics.” https://pmc.ncbi.nlm.nih.gov/articles/PMC8321025/
