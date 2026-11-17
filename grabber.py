"""Capture the local desktop to a PNG file; no upload or network transfer."""
import argparse
from pathlib import Path

def capture(path):
    import wx
    app=wx.App(False)
    try:
        screen=wx.ScreenDC()
        size=screen.GetSize()
        bitmap=wx.Bitmap(size[0],size[1])
        memory=wx.MemoryDC(bitmap)
        try:
            memory.Blit(0,0,size[0],size[1],screen,0,0)
        finally:
            memory.SelectObject(wx.NullBitmap)
        image=bitmap.ConvertToImage()
        with Path(path).open('xb') as stream:
            if not image.SaveFile(stream,wx.BITMAP_TYPE_PNG):
                raise OSError('failed to encode screenshot')
    finally:
        app.Destroy()

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    if args.output.suffix.lower() != '.png':
        parser.error('--output must end in .png')
    if args.output.exists():
        parser.error('output already exists; choose a new file')
    try:
        capture(args.output)
        print(f'Saved {args.output}')
        return 0
    except (ImportError,OSError,RuntimeError) as exc:
        parser.exit(2,f'error: {exc}; screenshot capture requires wxPython and a desktop session\n')

if __name__ == '__main__':
    raise SystemExit(main())
