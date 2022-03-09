# Strapi Clam AV Upload Provider Proxy

A Strapi upload provider proxy which will:

- Scan any file any user attempts to upload with Clam AV and reject if infected
- Optionally throw if GIF contains XSS attack
- Optionally remove XSS attack code from SVG type images
- Optionally remove XSS attack code from JPEG image EXIF fields

Before passing off upload to whichever other strapi-provider is appropriate for your use-case.

## Configuration

This plugin acts as a piggy-back onto whatever upload provider you would normally use.

Specify that provider in the `uploadProvider` option and then specify that providers options in-line with the clamav-proxy settings 


e.g. `config/plugins.js`


```js
module.exports = {
  ...
  upload: {
    provider: 'clamav-proxy',
    providerOptions: {
      clamav: {
        host: 'my.clamav.host',
        port: 3310,
        timeout: 3000
      },
      sanitize: {
        svg: true,
        jpeg: true,
        gif: true
      },
      // Proxied provider
      uploadProvider: 'strapi-provider-upload-local',
      sizeLimit: 100000
    }
  }
}
```

Where:

| Name                             | Type     | Description                                                     |
| -------------------------------- | -------- | --------------------------------------------------------------- |
| `provider`                       | Constant | "clamav-proxy" - The name of this provider                      |
| `providerOptions.clamav.host`    | String   | The hostname/ip of a ClamAV instance (default `127.0.0.1`)      |
| `providerOptions.clamav.post`    | Number   | The port on which that ClamAV instance runs (default `3310`)    |
| `providerOptions.clamav.timeout` | Number   | Clam AV timeout - ms (default `3000`)                           |
| `providerOptions.sanitize.svg`   | Boolean  | Sanitize SVG files?                                             |
| `providerOptions.sanitize.jpeg`  | Boolean  | Sanitize JPEG files?                                            |
| `providerOptions.sanitize.gif`   | Boolean  | Throw an error if GIF file is infected with an XSS attack       |                    |
| `providerOptions.uploadProvider` | String   | Any valid upload provider (e.g. `strapi-provider-upload-local`) |
| `providerOptions.*`              | Any      | Any valid upload provider option                                |
