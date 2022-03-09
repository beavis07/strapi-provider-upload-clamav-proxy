const createDomPurify = require('dompurify')
const clamd = require('clamdjs')
const piexifjs = require('piexifjs')
const { JSDOM } = require('jsdom')
const { omit } = require('lodash/fp')

/* Remove our config options from the config */
const cleanProviderOptions = omit(['uploadProvider', 'clamav', 'sanitize'])

/* Sanitize an SVG file using DOMPurify */
const DOMPurify = createDomPurify(new JSDOM('').window)
const sanitizeSVG = (buffer) =>
  Buffer.from(
    DOMPurify.sanitize(buffer.toString('utf8'), {
      USE_PROFILES: { svg: true, svgFilters: true },
    })
  )

/* Remove EXIF data from jpeg files */
const removeExif = (buffer) =>
  Buffer.from(piexifjs.remove(buffer.toString('binary')), 'binary')

module.exports = {
  init(options) {
    if (!options.uploadProvider) {
      throw new Error('ClamAV Proxy: missing uploadProvider setting')
    }

    const {
      clamav: { host = '127.0.0.1', port = 3301, timeout = 3000 },
      sanitize: sanitizeOptions,
    } = options

    /* Load and initialise the proxied provider */
    const uploadProvider = require(options.uploadProvider)
    const uploader = uploadProvider.init(cleanProviderOptions(options))

    /* Initialise the Clamb AV client */
    const scanner = clamd.createScanner(host, port)

    return {
      async upload(file) {
        if (sanitizeOptions) {
          sanitize(file, sanitizeOptions)
        }

        /* Scan the incoming file buffer */
        const reply = await scanner.scanBuffer(
          file.buffer,
          timeout,
          1024 * 1024
        )

        /* If the reply is "unclean" - return a formatted error */
        if (!clamd.isCleanReply(reply)) {
          const virus = reply.replace('stream:', '').replace(' FOUND', '').trim()
          throw new Error(`This file is infected with a virus: ${virus}`)
        }

        /* Proxy the file upload request */
        return uploader.upload(file)
      },
      delete(file) {
        /* Proxy the file upload request */
        return uploader.delete(file)
      },
    }
  },
}

/* Clean images of XSS attacks etc - throw an error if we find something we can't fix! */
function sanitize(file, options) {
  if (options.svg && (file.ext === '.svg' || file.mime === 'image/svg+xml')) {
    /* If file is SVG, purify the DOM to remove XSS attacks etc */
    file.buffer = sanitizeSVG(file.buffer)
  } else if (
    options.jpeg &&
    (['.jpg', '.jpeg'].includes(file.ext) || file.mime === 'image/jpeg')
  ) {
    /* If file is JPEG, remove all EXIF data */
    file.buffer = removeExif(file.buffer)
  } else if (
    options.gif &&
    (file.ext === '.gif' || file.mime === 'image/gif')
  ) {
    /* If file is a GIF and it contains as XSS hack - reject it */
    if (file.buffer.toString('ascii').startsWith('GIF89a/*')) {
      throw new Error('GIF89a file contains XSS attack')
    }
  }
}
