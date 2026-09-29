'use strict'

/**
 * static files (404.html, sw.js, conf.js)
 */
const ASSET_URL = 'https://git-page.snorbo.vip/'
const PREFIX = '/'

// ==================== 认证配置 ====================
// 密码以 SHA-256 哈希形式存储，不存储明文
// Asd19569 的 SHA-256 十六进制值（小写），由第一步的命令生成
const AUTH_PASSWORD_HASH = '22ccbb87ecffa2717fa832c83e0132ee968e9236e048be1573373cce6a32b45e'

// Cookie 签名密钥，建议用随机字符串，不要和密码有关
// 生成方法：node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const AUTH_SECRET = '874b56bdeaac120e9ad175401622de72f074301563a5f6bbce688bcdd999e58e'

const COOKIE_NAME = 'git_proxy_auth'
const COOKIE_MAX_AGE = 7 * 24 * 3600  // 7 天
// ==================================================

const Config = {
    jsdelivr: 0
}

const whiteList = []

/** @type {ResponseInit} */
const PREFLIGHT_INIT = {
    status: 204,
    headers: new Headers({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
        'access-control-max-age': '1728000',
    }),
}

const exp1 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive)\/.*$/i
const exp2 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i
const exp3 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:info|git-).*$/i
const exp4 = /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i
const exp5 = /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i
const exp6 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/tags.*$/i

function makeRes(body, status = 200, headers = {}) {
    headers['access-control-allow-origin'] = '*'
    return new Response(body, { status, headers })
}

function newUrl(urlStr) {
    try {
        return new URL(urlStr)
    } catch (err) {
        return null
    }
}

// ==================== 认证工具函数 ====================

async function sha256Hex(text) {
    const encoder = new TextEncoder()
    const data = encoder.encode(text)
    const hash = await crypto.subtle.digest('SHA-256', data)
    const bytes = new Uint8Array(hash)
    let hex = ''
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0')
    }
    return hex
}

async function verifyPassword(input) {
    if (!input) return false
    const inputHash = await sha256Hex(input)
    if (inputHash.length !== AUTH_PASSWORD_HASH.length) return false
    // 常量时间比较，避免时序攻击
    let diff = 0
    for (let i = 0; i < inputHash.length; i++) {
        diff |= inputHash.charCodeAt(i) ^ AUTH_PASSWORD_HASH.charCodeAt(i)
    }
    return diff === 0
}

function toUrlSafeBase64(str) {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function hmacSign(data) {
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(AUTH_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    )
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
    const bytes = new Uint8Array(sig)
    let binary = ''
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
    return toUrlSafeBase64(btoa(binary))
}

async function generateToken() {
    return await hmacSign(AUTH_PASSWORD_HASH)
}

async function verifyToken(token) {
    if (!token) return false
    const expected = await generateToken()
    if (token.length !== expected.length) return false
    let diff = 0
    for (let i = 0; i < token.length; i++) {
        diff |= token.charCodeAt(i) ^ expected.charCodeAt(i)
    }
    return diff === 0
}

function parseCookies(cookieHeader) {
    const cookies = {}
    if (!cookieHeader) return cookies
    cookieHeader.split(';').forEach(pair => {
        const idx = pair.indexOf('=')
        if (idx > 0) {
            const k = pair.slice(0, idx).trim()
            const v = pair.slice(idx + 1).trim()
            cookies[k] = v
        }
    })
    return cookies
}

const LOGIN_PAGE_TPL = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>需要验证</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:linear-gradient(135deg,#1e3c72 0%,#2a5298 100%);
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .card{background:#fff;padding:40px 36px;border-radius:12px;
        box-shadow:0 20px 60px rgba(0,0,0,.3);width:100%;max-width:380px}
  h1{margin:0 0 8px;font-size:22px;color:#1e3c72;text-align:center}
  p.sub{margin:0 0 24px;font-size:13px;color:#888;text-align:center}
  input[type=password]{width:100%;padding:12px 14px;font-size:15px;
        border:1px solid #ddd;border-radius:8px;outline:none;transition:border-color .2s}
  input[type=password]:focus{border-color:#2a5298}
  button{width:100%;margin-top:16px;padding:12px;font-size:15px;font-weight:600;
         color:#fff;background:#2a5298;border:none;border-radius:8px;cursor:pointer;
         transition:background .2s}
  button:hover{background:#1e3c72}
  .error{margin-top:12px;padding:10px;background:#fee;color:#c00;border-radius:6px;
         font-size:13px;text-align:center;display:__ERROR_DISPLAY__}
</style>
</head>
<body>
  <form class="card" method="POST" action="/__login">
    <h1>🔒 需要验证</h1>
    <p class="sub">请输入访问密码</p>
    <input type="password" name="password" placeholder="密码" autofocus required>
    <button type="submit">进入</button>
    <div class="error">密码错误，请重试</div>
  </form>
</body>
</html>`

async function handleLogin(req) {
    const urlObj = new URL(req.url)
    const isError = urlObj.searchParams.get('error') === '1'

    if (req.method === 'GET') {
        const html = LOGIN_PAGE_TPL.replace('__ERROR_DISPLAY__', isError ? 'block' : 'none')
        return new Response(html, {
            status: 200,
            headers: { 'content-type': 'text/html; charset=utf-8' }
        })
    }

    if (req.method === 'POST') {
        let password = ''
        try {
            const formData = await req.formData()
            password = String(formData.get('password') || '')
        } catch (e) {
            return Response.redirect(new URL('/__login?error=1', urlObj.origin).href, 302)
        }

        if (await verifyPassword(password)) {
            const token = await generateToken()
            let redirectTo = urlObj.searchParams.get('redirect') || '/'
            if (!redirectTo.startsWith('/') || redirectTo.startsWith('//')) {
                redirectTo = '/'
            }
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': redirectTo,
                    'Set-Cookie': `${COOKIE_NAME}=${token}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`
                }
            })
        }

        return Response.redirect(new URL('/__login?error=1', urlObj.origin).href, 302)
    }

    return new Response('Method Not Allowed', { status: 405 })
}

function handleLogout() {
    return new Response(null, {
        status: 302,
        headers: {
            'Location': '/__login',
            'Set-Cookie': `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
        }
    })
}

// ==================== 主流程 ====================

addEventListener('fetch', e => {
    const ret = fetchHandler(e)
        .catch(err => makeRes('cfworker error:\n' + err.stack, 502))
    e.respondWith(ret)
})

function checkUrl(u) {
    for (let i of [exp1, exp2, exp3, exp4, exp5, exp6]) {
        if (u.search(i) === 0) {
            return true
        }
    }
    return false
}

async function fetchHandler(e) {
    const req = e.request
    const urlObj = new URL(req.url)

    // ---- 认证路径，无需验证 ----
    if (urlObj.pathname === '/__login') {
        return handleLogin(req)
    }
    if (urlObj.pathname === '/__logout') {
        return handleLogout()
    }

    // ---- 认证检查 ----
    const cookies = parseCookies(req.headers.get('cookie'))
    const token = cookies[COOKIE_NAME]
    if (!await verifyToken(token)) {
        const loginUrl = new URL('/__login', urlObj.origin)
        const redirect = urlObj.pathname + urlObj.search
        loginUrl.searchParams.set('redirect', redirect)
        return Response.redirect(loginUrl.href, 302)
    }

    // ---- 原有逻辑 ----
    let path = urlObj.searchParams.get('q')
    if (path) {
        return Response.redirect('https://' + urlObj.host + PREFIX + path, 301)
    }
    path = urlObj.href.slice(urlObj.origin.length + PREFIX.length).replace(/^https?:\/+/, 'https://')
    if (path.search(exp1) === 0 || path.search(exp5) === 0 || path.search(exp6) === 0 || path.search(exp3) === 0) {
        return httpHandler(req, path)
    } else if (path.search(exp2) === 0) {
        if (Config.jsdelivr) {
            const newUrl = path.replace('/blob/', '@').replace(/^(?:https?:\/\/)?github\.com/, 'https://cdn.jsdelivr.net/gh')
            return Response.redirect(newUrl, 302)
        } else {
            path = path.replace('/blob/', '/raw/')
            return httpHandler(req, path)
        }
    } else if (path.search(exp4) === 0) {
        if (Config.jsdelivr) {
            const newUrl = path.replace(/(?<=com\/.+?\/.+?)\/(.+?\/)/, '@$1').replace(/^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com/, 'https://cdn.jsdelivr.net/gh')
            return Response.redirect(newUrl, 302)
        }
        else {
            return httpHandler(req, path)
        }
    } else {
        return fetch(ASSET_URL + path)
    }
}

function httpHandler(req, pathname) {
    const reqHdrRaw = req.headers

    if (req.method === 'OPTIONS' &&
        reqHdrRaw.has('access-control-request-headers')
    ) {
        return new Response(null, PREFLIGHT_INIT)
    }

    const reqHdrNew = new Headers(reqHdrRaw)

    let urlStr = pathname
    let flag = !Boolean(whiteList.length)
    for (let i of whiteList) {
        if (urlStr.includes(i)) {
            flag = true
            break
        }
    }
    if (!flag) {
        return new Response("blocked", { status: 403 })
    }
    if (urlStr.search(/^https?:\/\//) !== 0) {
        urlStr = 'https://' + urlStr
    }
    const urlObj = newUrl(urlStr)

    const reqInit = {
        method: req.method,
        headers: reqHdrNew,
        redirect: 'manual',
        body: req.body
    }
    return proxy(urlObj, reqInit)
}

async function proxy(urlObj, reqInit) {
    const res = await fetch(urlObj.href, reqInit)
    const resHdrOld = res.headers
    const resHdrNew = new Headers(resHdrOld)

    const status = res.status

    if (resHdrNew.has('location')) {
        let _location = resHdrNew.get('location')
        if (checkUrl(_location))
            resHdrNew.set('location', PREFIX + _location)
        else {
            reqInit.redirect = 'follow'
            return proxy(newUrl(_location), reqInit)
        }
    }
    resHdrNew.set('access-control-expose-headers', '*')
    resHdrNew.set('access-control-allow-origin', '*')

    resHdrNew.delete('content-security-policy')
    resHdrNew.delete('content-security-policy-report-only')
    resHdrNew.delete('clear-site-data')

    return new Response(res.body, {
        status,
        headers: resHdrNew,
    })
}
