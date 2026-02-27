#!/usr/bin/env python3
"""Generate a standalone GitHub Pages demo page from the dashboard source.

Injects a fetch interceptor that returns simulated burner data so the
dashboard renders correctly without a real Pico W device.

Usage:
    gen_demo_page.py INPUT_HTML OUTPUT_HTML
"""

import re
import sys

# Injected before the first <script> tag so fetch is mocked before any code runs.
_MOCK_SCRIPT = """\
<script>
/* Demo mode: intercept API calls and return simulated burner data */
(function () {
  var samples = [
    {flame: true,  fan: 65, temp: 72, err: 0, valid: true, flame_secs: 7320},
    {flame: true,  fan: 70, temp: 74, err: 0, valid: true, flame_secs: 7322},
    {flame: true,  fan: 60, temp: 71, err: 0, valid: true, flame_secs: 7324},
    {flame: false, fan: 0,  temp: 68, err: 0, valid: true, flame_secs: 7324},
    {flame: false, fan: 0,  temp: 65, err: 0, valid: true, flame_secs: 7324}
  ];
  var idx = 0;
  var _fetch = window.fetch.bind(window);
  window.fetch = function (url, opts) {
    if (url === '/api/data') {
      var d = samples[idx % samples.length]; idx++;
      return Promise.resolve({ok: true, json: function () { return Promise.resolve(d); }});
    }
    if (url === '/api/country') {
      return Promise.resolve({ok: true, json: function () { return Promise.resolve({country: 'SE'}); }});
    }
    if (url === '/api/vapid-public-key') {
      return Promise.resolve({ok: true, json: function () { return Promise.resolve({key: ''}); }});
    }
    if (opts && opts.method === 'POST') {
      return Promise.resolve({ok: true, json: function () { return Promise.resolve({status: 'ok'}); }});
    }
    return _fetch(url, opts);
  };
}());
</script>
"""

# Appended after the last </script> tag to override the push-notification
# function with a demo-mode message (must run after the original definition).
_PUSH_OVERRIDE_SCRIPT = """\
<script>
/* Demo mode: replace push-notification toggle with an informational message */
window.togglePush = function () {
  alert('Push notifications require the actual Pico W device.\nThis is a demo running simulated data.');
};
</script>
"""

# Inserted immediately after the opening <body> tag.
_DEMO_BANNER = (
    '<div style="background:#2d4a1e;color:#7dce82;text-align:center;'
    'padding:10px;border-radius:8px;margin-bottom:16px;font-size:.85em">'
    '&#128250; Demo mode &mdash; simulated data. '
    '<a href="https://github.com/phieri/viking-bio-pwa" '
    'style="color:#a8e6b0">View project on GitHub</a></div>'
)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} INPUT_HTML OUTPUT_HTML", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, 'r', encoding='utf-8') as f:
        html = f.read()

    # 1. Inject demo banner after <body>
    html = re.sub(r'(<body>)', r'\1\n' + _DEMO_BANNER, html, count=1, flags=re.IGNORECASE)

    # 2. Inject mock fetch interceptor before the first <script> tag
    html = re.sub(r'(<script>)', _MOCK_SCRIPT + r'\1', html, count=1, flags=re.IGNORECASE)

    # 3. Append push-notification override after the last </script>
    m = None
    for m in re.finditer(r'</script>', html, flags=re.IGNORECASE):
        pass
    if m is not None:
        insert_pos = m.end()
        html = html[:insert_pos] + '\n' + _PUSH_OVERRIDE_SCRIPT + html[insert_pos:]

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"Generated demo page: {output_file}")


if __name__ == '__main__':
    main()
