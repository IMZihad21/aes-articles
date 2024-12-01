In today's world of web development, securing the transmission of sensitive data over the internet is of paramount importance. A critical aspect of this security is ensuring that both HTTP requests and responses are encrypted. This article demonstrates how to implement a custom HTTP encryption mechanism in an ASP.NET Core Web API using a combination of attributes, filters, and AES encryption.

We'll walk through the process of creating an HttpEncryptionAttribute that encrypts and decrypts HTTP request and response bodies. This solution ensures that any sensitive data in transit is securely encrypted before being sent over the wire and decrypted once it reaches the server or client.

## Prerequisites

To follow along with this guide, you'll need:

- A basic understanding of ASP.NET Core and its middleware pipeline.
- Familiarity with encryption concepts, particularly AES encryption.
- .NET 6 or later for compatibility with the latest features and libraries.

## Overview of the Approach

The approach leverages an attribute-based filter system to automatically encrypt and decrypt data as part of the request and response lifecycle. This is achieved through the use of custom attributes (`HttpEncryptionAttribute`) and filters (`HttpEncryptionAttributeFilter`), which interact with the HTTP context to encrypt or decrypt streams using AES encryption.

Let's break down the code step by step:

## Step 1: The `HttpEncryptionAttribute`
The `HttpEncryptionAttribute` is the core of this solution. This custom attribute is applied to controllers or actions that require encryption. It implements the `IFilterFactory` interface, allowing it to produce a filter when applied.

```csharp
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class HttpEncryptionAttribute : Attribute, IFilterFactory
{
    public bool IsReusable => false;

    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        var config = serviceProvider.GetRequiredService<IOptions<ApplicationConfiguration>>();
        return new HttpEncryptionAttributeFilter(config.Value);
    }
}

```

- `AttributeUsage`: Specifies that this attribute can be applied to both classes and methods.
- `CreateInstance`: When the attribute is applied, this method is invoked to create an instance of `HttpEncryptionAttributeFilter`, passing in the application configuration (such as the encryption key) from the DI container.

## Step 2: The `HttpEncryptionAttributeFilter`
The `HttpEncryptionAttributeFilter` is responsible for intercepting the request and response flows. It implements the `IAsyncResourceFilter` interface, which provides hooks to run code before and after an action executes. The encryption and decryption logic are handled here.

```csharp
public class HttpEncryptionAttributeFilter : IAsyncResourceFilter
{
    private readonly Aes _aes;

    public HttpEncryptionAttributeFilter(ApplicationConfiguration appConfig)
    {
        _aes = GenerateAes(appConfig.HttpEncryptionKey);
    }

    public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
    {
        context.HttpContext.Request.Body = DecryptStream(context.HttpContext.Request.Body);
        context.HttpContext.Response.Body = EncryptStream(context.HttpContext.Response.Body);

        if (context.HttpContext.Request.QueryString.HasValue)
        {
            var decryptedQueryString = DecryptString(context.HttpContext.Request.QueryString.Value[1..]);
            context.HttpContext.Request.QueryString = new QueryString($"?{decryptedQueryString}");
        }

        await next();
        await context.HttpContext.Request.Body.DisposeAsync();
        await context.HttpContext.Response.Body.DisposeAsync();
    }

    private CryptoStream EncryptStream(Stream responseStream)
    {
        var encryptor = _aes.CreateEncryptor();
        var base64Transform = new ToBase64Transform();
        var base64EncodedStream = new CryptoStream(responseStream, base64Transform, CryptoStreamMode.Write);
        return new CryptoStream(base64EncodedStream, encryptor, CryptoStreamMode.Write);
    }

    private CryptoStream DecryptStream(Stream cipherStream)
    {
        var decryptor = _aes.CreateDecryptor();
        var base64Transform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);
        var base64DecodedStream = new CryptoStream(cipherStream, base64Transform, CryptoStreamMode.Read);
        return new CryptoStream(base64DecodedStream, decryptor, CryptoStreamMode.Read);
    }

    private string DecryptString(string cipherText)
    {
        using var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText));
        using var cryptoStream = new CryptoStream(memoryStream, _aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new StreamReader(cryptoStream);
        return reader.ReadToEnd();
    }

    private static Aes GenerateAes(string encryptionKey)
    {
        var key = encryptionKey.PadRight(32, '0');
        var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key[..32]);
        aes.IV = Encoding.UTF8.GetBytes(key[..16]);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        return aes;
    }
}
```

- `OnResourceExecutionAsync`: This is the main method where the request and response streams are encrypted and decrypted. The request body is decrypted before the action executes, and the response body is encrypted before being sent back to the client.
- `DecryptStream` and `EncryptStream`: These methods wrap the original request/response streams with `CryptoStream` objects, applying AES decryption and encryption, respectively.
- `DecryptString`: This method is used to decrypt query strings if they are present in the request.

## Step 3: AES Encryption Logic
The encryption mechanism uses the AES algorithm, a symmetric encryption standard, to handle the encryption and decryption of data. AES is configured with a key and initialization vector (IV) derived from the `HttpEncryptionKey` provided in the application configuration.

```csharp
private static Aes GenerateAes(string encryptionKey)
{
    var key = encryptionKey.PadRight(32, '0');
    var aes = Aes.Create();
    aes.Key = Encoding.UTF8.GetBytes(key[..32]);
    aes.IV = Encoding.UTF8.GetBytes(key[..16]);
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;
    return aes;
}
```

- Key & IV: The AES key is derived from the provided encryption key. If the key is shorter than required, it is padded. The IV is extracted from the first 16 bytes of the encryption key.
- Padding: `PKCS7` padding is used to ensure that the data length is a multiple of the block size.

## Step 4: Applying the Attribute
To apply the encryption to your API endpoints, simply decorate your controllers or actions with the `HttpEncryptionAttribute`.

```csharp
[HttpEncryption]
[Route("api/[controller]")]
public class SensitiveDataController : ControllerBase
{
    [HttpPost]
    public IActionResult PostSensitiveData([FromBody] SensitiveData data)
    {
        // Sensitive data processing logic
        return Ok();
    }
}
```

This ensures that both the request and response data are automatically encrypted and decrypted by the `HttpEncryptionAttributeFilter`.

## Conclusion

This solution leverages ASP.NET Core's powerful middleware and filter mechanisms to seamlessly encrypt and decrypt HTTP request and response bodies. By using custom attributes and filters, you can secure sensitive data in your API without modifying the individual actions or controllers. This is particularly useful when you need to enforce encryption across an entire set of endpoints with minimal overhead.

Incorporating encryption at this level ensures that your API meets security standards for data-in-transit encryption, mitigating risks associated with man-in-the-middle attacks and ensuring the privacy and integrity of sensitive data.