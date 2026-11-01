#!/usr/bin/env python3
"""Compose demo-video capture + narration without FFmpeg's optional libass.

Usage: python render.py CAPTURE_DIR OUTPUT_DIR
Requires Pillow, ffmpeg and ffprobe. Reads the Hmache/demo capture format.
"""
import json
from pathlib import Path
import subprocess
import sys
from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 1920, 1080, 30
BG, FG, ACCENT = '#f5f5f7', '#1d1d1f', '#0066cc'
INTRO, OUTRO = 3, 4


def run(args):
    subprocess.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error', *args], check=True)


def font(size, bold=False):
    system_font = Path('/System/Library/Fonts/SFNS.ttf')
    if system_font.exists():
        face = ImageFont.truetype(str(system_font), size)
        face.set_variation_by_name('Semibold' if bold else 'Regular')
        return face
    names = [
        f'/System/Library/Fonts/Supplemental/Arial{" Bold" if bold else ""}.ttf',
        f'/usr/share/fonts/truetype/dejavu/DejaVuSans{"-Bold" if bold else ""}.ttf',
    ]
    for name in names:
        if Path(name).exists():
            return ImageFont.truetype(name, size)
    raise RuntimeError('Install Arial or DejaVu Sans before rendering.')


def wrap(draw, text, face, width):
    lines, line = [], ''
    for word in text.split():
        trial = (line + ' ' + word).strip()
        if line and draw.textlength(trial, font=face) > width:
            lines.append(line)
            line = word
        else:
            line = trial
    if line:
        lines.append(line)
    return lines


def timestamp(seconds, separator='.'):
    millis = round(max(0, seconds) * 1000)
    seconds, ms = divmod(millis, 1000)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f'{hours:02}:{minutes:02}:{seconds:02}{separator}{ms:03}'


def concat_entry(path, duration):
    if "'" in str(path):
        raise ValueError('Use a render directory without apostrophes.')
    return f"file '{path.resolve()}'\nduration {duration:.6f}\n"


def card(path, ending=False):
    im = Image.new('RGB', (W, H), BG)
    d = ImageDraw.Draw(im)
    title = 'GadgetHunter'
    subtitle = 'github.com/MarkLee131/GadgetHunter' if ending else 'Workbench demo'
    d.text(((W - d.textlength(title, font=font(104, True))) / 2, 400), title,
           font=font(104, True), fill=FG)
    d.text(((W - d.textlength(subtitle, font=font(36))) / 2, 550), subtitle,
           font=font(36), fill=ACCENT if ending else '#626269')
    im.save(path)


def main(capture, output):
    capture, output = Path(capture).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    edit = capture / 'edit'
    edit.mkdir(exist_ok=True)
    timing = json.loads((capture / 'timing.json').read_text())
    frames = json.loads((capture / 'frames.json').read_text())
    start, end = timing['trimStart'], timing['end']
    duration = end - start
    steps = timing['steps']
    assert duration > 0 and steps

    # Real browser frame timestamps, including cursor movement and scrolling.
    selected = [f for f in frames if f['t'] >= start]
    earlier = [f for f in frames if f['t'] < start]
    if earlier:
        selected.insert(0, {'f': earlier[-1]['f'], 't': start})
    if not selected:
        raise ValueError('No browser frames captured.')
    listing = ''
    for a, b in zip(selected, selected[1:] + [{'t': end}]):
        listing += concat_entry(capture / 'frames' / a['f'], max(.001, b['t'] - a['t']))
    listing += f"file '{capture / 'frames' / selected[-1]['f']}'\n"
    (edit / 'frames.txt').write_text(listing)

    # Mix each generated line at its recorded scene start.
    inputs, filters, labels = [], [], []
    for n, step in enumerate(steps):
        audio = capture / 'audio' / f"step_{step['i']:02d}.wav"
        inputs += ['-i', str(audio)]
        offset = round((step['start'] - start) * 1000)
        filters.append(f'[{n}:a]adelay={offset}:all=1[a{n}]')
        labels.append(f'[a{n}]')
    filters.append(''.join(labels) + f'amix=inputs={len(labels)}:normalize=0,apad,atrim=duration={duration:.6f}[voice]')
    run([*inputs, '-filter_complex', ';'.join(filters), '-map', '[voice]', '-ar', '44100', '-ac', '2', str(capture / 'voice.wav')])

    # Transparent chapter/caption overlays, kept outside the product viewport.
    overlay_list, vtt, srt = '', ['WEBVTT\n'], []
    for n, step in enumerate(steps):
        overlay = Image.new('RGBA', (W, H), (0, 0, 0, 0))
        d = ImageDraw.Draw(overlay)
        lines = wrap(d, step['say'], font(30), 1580)
        if len(lines) > 2:
            raise ValueError(f'Caption too long in step {n}: shorten the narration.')
        y = 984 if len(lines) == 2 else 1002
        for line in lines:
            d.text(((W - d.textlength(line, font=font(30))) / 2, y), line, font=font(30), fill=FG)
            y += 36
        d.rectangle((0, 1076, round(W * (n + 1) / len(steps)), 1079), fill=ACCENT)
        png = edit / f'overlay-{n:02}.png'
        overlay.save(png)
        scene_end = steps[n + 1]['start'] if n + 1 < len(steps) else end
        overlay_list += concat_entry(png, scene_end - step['start'])
        a, b = step['start'] - start + INTRO, step['end'] - start + INTRO
        vtt.append(f'{timestamp(a)} --> {timestamp(b)}\n{step["say"]}\n')
        srt.append(f'{n + 1}\n{timestamp(a, ",")} --> {timestamp(b, ",")}\n{step["say"]}\n')
    overlay_list += f"file '{png}'\n"
    (edit / 'overlays.txt').write_text(overlay_list)
    (output / 'gadgethunter-demo.en.vtt').write_text('\n'.join(vtt))
    (output / 'gadgethunter-demo.en.srt').write_text('\n'.join(srt))

    body = edit / 'body.mp4'
    run(['-f', 'concat', '-safe', '0', '-i', str(edit / 'frames.txt'),
         '-f', 'concat', '-safe', '0', '-i', str(edit / 'overlays.txt'), '-i', str(capture / 'voice.wav'),
         '-filter_complex', f'[0:v]fps={FPS},scale=1728:918:flags=lanczos,pad={W}:{H}:96:32:color={BG},setsar=1[base];[1:v]fps={FPS},format=rgba[caption];[base][caption]overlay=0:0:shortest=1,format=yuv420p[v]',
         '-map', '[v]', '-map', '2:a', '-t', f'{duration:.6f}', '-c:v', 'libx264', '-preset', 'fast', '-crf', '20',
         '-c:a', 'aac', '-b:a', '160k', '-ar', '44100', '-ac', '2', '-movflags', '+faststart', str(body)])

    clips = []
    for name, seconds, ending in [('intro', INTRO, False), ('outro', OUTRO, True)]:
        png, video = edit / f'{name}.png', edit / f'{name}.mp4'
        card(png, ending)
        run(['-loop', '1', '-framerate', str(FPS), '-i', str(png), '-f', 'lavfi', '-i', 'anullsrc=r=44100:cl=stereo',
             '-t', str(seconds), '-c:v', 'libx264', '-preset', 'fast', '-crf', '20', '-pix_fmt', 'yuv420p',
             '-c:a', 'aac', '-b:a', '160k', '-ar', '44100', '-ac', '2', str(video)])
        clips.append(video)
    (edit / 'clips.txt').write_text(''.join(f"file '{p}'\n" for p in [clips[0], body, clips[1]]))
    video = output / 'gadgethunter-demo.mp4'
    run(['-f', 'concat', '-safe', '0', '-i', str(edit / 'clips.txt'), '-c', 'copy', '-movflags', '+faststart', str(video)])
    Image.open(edit / 'intro.png').save(output / 'gadgethunter-demo-poster.jpg', quality=92)
    (capture / 'offsets.json').write_text(json.dumps({'intro': INTRO}))
    transcript = ['GadgetHunter workbench walkthrough', 'English narration generated with OpenAI gpt-4o-mini-tts, voice marin.',
                  'Real workbench recording. Static-analysis fixture and a separate saved harmless validation report.\n']
    transcript.extend(f'{s["label"]}\n{s["say"]}\n' for s in steps)
    (output / 'gadgethunter-demo-transcript.txt').write_text('\n'.join(transcript))
    print(f'Rendered {video}: {duration + INTRO + OUTRO:.1f}s, {W}x{H}, {FPS} fps', flush=True)


if __name__ == '__main__':
    main(*sys.argv[1:])
