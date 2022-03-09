const createDomPurify = require('dompurify')
const clamd = require('clamdjs')
const piexifjs = require('piexifjs')
const { JSDOM } = require('jsdom')
const { errors } = require('strapi-plugin-upload')
const { omit } = require('lodash/fp')

/* Remove our config options from the config */
const cleanProviderOptions = omit(['uploadProvider', 'clamav'])

/* Format an error response from ClamAV */
const virusError = (reply) => {
  const virus = reply.replace('stream:', '').replace(' FOUND', '').trim()
  return errors.unknownError(`This file is infected with a virus: ${virus}`)
}

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

    if (!options.clamav) {
      throw new Error('ClamAV Proxy: missing clamav settings')
    }

    /* Load and initialise the proxied provider */
    const uploadProvider = require(options.uploadProvider)
    const uploader = uploadProvider.init(cleanProviderOptions(options))

    /* Initialise the Clamb AV client */
    const scanner = clamd.createScanner(
      options.clamav.host,
      options.clamav.port
    )

    return {
      async upload(file) {
        if (options.sanitize) {
          sanitize(file, options.sanitize)
        }

        /* Scan the incoming file buffer */
        const reply = await scanner.scanBuffer(
          file.buffer,
          options.clamav.timeout,
          1024 * 1024
        )

        /* If the reply is "unclean" - return a formatted error */
        if (!clamd.isCleanReply(reply)) {
          throw virusError(reply)
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
      throw virusError('GIF contains XSS attack')
    }
  }
}
