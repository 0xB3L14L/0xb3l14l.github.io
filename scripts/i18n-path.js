'use strict'

/**
 * Make Spanish the default language (no /es prefix) and keep English under /en/...
 * This filter adjusts the generated path for posts and pages based on front-matter `lang`.
 */

const pathFn = require('path')

hexo.extend.filter.register('after_post_render', function (data) {
  try {
    if (!data || !data.path) return data
    const lang = (data.lang || 'es').toString().toLowerCase()
    if (lang === 'en') {
      if (!data.path.startsWith('en/')) data.path = pathFn.posix.join('en', data.path)
    } else {
      // Remove any starting es/
      data.path = data.path.replace(/^es\//, '')
    }
    return data
  } catch (_) {
    return data
  }
})

// Ensure paths are set correctly right before generation
hexo.extend.filter.register('before_generate', function () {
  try {
    const posts = hexo.locals.get('posts')
    posts && posts.forEach(post => {
      const lang = (post.lang || 'es').toString().toLowerCase()
      if (lang === 'en') {
        if (!post.path.startsWith('en/')) post.path = 'en/' + post.path
      } else {
        post.path = post.path.replace(/^es\//, '')
      }
    })

    const pages = hexo.locals.get('pages')
    pages && pages.forEach(page => {
      const lang = (page.lang || 'es').toString().toLowerCase()
      if (lang === 'en') {
        if (!page.path.startsWith('en/')) page.path = 'en/' + page.path
      } else {
        page.path = page.path.replace(/^es\//, '')
      }
    })
  } catch (_) {
    // ignore
  }
})


