using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Dalamud.Plugin.Internal;
using Dalamud.Utility;

using Serilog;

namespace Dalamud.Networking.Http;

/// <summary>
/// A service to help build and manage HttpClients with some semblance of Happy Eyeballs (RFC 8305 - IPv4 fallback)
/// awareness.
/// </summary>
[ServiceManager.BlockingEarlyLoadedService($"{nameof(PluginManager)} currently uses this.")]
// ^ TODO: This seems unnecessary, remove the hard dependency at a later time.
//         Otherwise, if PM eventually marks this class as required, note that in the comment above.
internal class HappyHttpClient : IInternalDisposableService
{
    /// <summary>
    /// SPKI SHA-256 hashes (base64) that we trust for ffxivplugins.commslink.net.
    /// Primary = leaf key, backup = Let's Encrypt intermediate.
    /// A compromised CA cannot MITM plugin downloads unless they also have one of these keys.
    /// </summary>
    private static readonly HashSet<string> PinnedSpkiHashes =
    [
        "kBfonzK8yg2GwgZSBzKhOTMvHsYmD15HFTlSDE3ae2k=", // leaf key
        "iFvwVyJSxnQdyaUvUERIf+8qk7gRze3612JMwoO3zdU=", // Let's Encrypt R11 intermediate (backup)
    ];

    /// <summary>
    /// The hostname to enforce certificate pinning on.
    /// All other hosts use standard TLS validation (no pinning).
    /// </summary>
    private const string PinnedHostname = "ffxivplugins.commslink.net";

    /// <summary>
    /// Initializes a new instance of the <see cref="HappyHttpClient"/> class.
    ///
    /// A service to talk to the Smileton Loporrits to build an HTTP Client aware of Happy Eyeballs.
    /// </summary>
    [ServiceManager.ServiceConstructor]
    private HappyHttpClient()
    {
        this.SharedHappyEyeballsCallback = new HappyEyeballsCallback();

        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            ConnectCallback = this.SharedHappyEyeballsCallback.ConnectCallback,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = ValidateCertificatePin,
            },
        };

        this.SharedHttpClient = new HttpClient(handler)
        {
            DefaultRequestHeaders =
            {
                UserAgent =
                {
                    new ProductInfoHeaderValue("Dalamud", Versioning.GetAssemblyVersion()),
                },
            },
        };
    }

    /// <summary>
    /// Gets a <see cref="HttpClient"/> meant to be shared across all (standard) requests made by the application,
    /// where custom configurations are not required.
    ///
    /// May or may not have been properly tested by the Loporrits.
    /// </summary>
    public HttpClient SharedHttpClient { get; }

    /// <summary>
    /// Gets a <see cref="HappyEyeballsCallback"/> meant to be shared across any custom <see cref="HttpClient"/>s that
    /// need to be made in other parts of the application.
    ///
    /// This should be used when shared callback state is desired across multiple clients, as sharing the SocketsHandler
    /// may lead to GC issues.
    /// </summary>
    public HappyEyeballsCallback SharedHappyEyeballsCallback { get; }

    /// <inheritdoc/>
    void IInternalDisposableService.DisposeService()
    {
        this.SharedHttpClient.Dispose();
        this.SharedHappyEyeballsCallback.Dispose();

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// TLS certificate validation callback that enforces SPKI pinning for our API domain.
    /// For all other hosts, standard platform validation applies (returns true if the chain is valid).
    /// </summary>
    private static bool ValidateCertificatePin(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // For non-pinned hosts, fall back to default validation.
        if (sender is SslStream ssl && ssl.TargetHostName != PinnedHostname)
            return sslPolicyErrors == SslPolicyErrors.None;
        if (sender is HttpRequestMessage req && req.RequestUri?.Host != PinnedHostname)
            return sslPolicyErrors == SslPolicyErrors.None;

        // Standard TLS errors are still fatal.
        if (sslPolicyErrors != SslPolicyErrors.None)
        {
            Log.Warning("TLS validation failed for {Host}: {Errors}", PinnedHostname, sslPolicyErrors);
            return false;
        }

        if (chain == null || certificate == null)
            return false;

        // Check every certificate in the chain — if any matches a pinned SPKI, we're good.
        foreach (var element in chain.ChainElements)
        {
            using var cert = element.Certificate;
            var spkiHash = Convert.ToBase64String(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo()));
            if (PinnedSpkiHashes.Contains(spkiHash))
            {
                Log.Verbose("Certificate pin matched for {Host}: {Hash}", PinnedHostname, spkiHash);
                return true;
            }
        }

        // Also check the leaf certificate directly (sender may provide it outside the chain).
        using var leaf = new X509Certificate2(certificate);
        var leafHash = Convert.ToBase64String(SHA256.HashData(leaf.PublicKey.ExportSubjectPublicKeyInfo()));
        if (PinnedSpkiHashes.Contains(leafHash))
        {
            Log.Verbose("Certificate pin matched (leaf) for {Host}: {Hash}", PinnedHostname, leafHash);
            return true;
        }

        Log.Error(
            "Certificate pin FAILED for {Host}. Leaf SPKI: {LeafHash}. " +
            "This may indicate a MITM attack or a certificate rotation that requires a client update.",
            PinnedHostname,
            leafHash);
        return false;
    }
}
