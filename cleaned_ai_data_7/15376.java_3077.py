import os
from urllib.parse import urlparse

class SubtitleUtils:
    @staticmethod
    def get_subtitle_mime(uri):
        path = uri.path
        if path.endswith('.ssa') or path.endswith('.ass'):
            return 'text/ssa'
        elif path.endswith('.vtt'):
            return 'text/vtt'
        elif path.endswith('.ttml') or path.endswith('.xml') or path.endswith('.dfxp'):
            return 'application/ttml+xml'
        else:
            return 'application/subrip'

    @staticmethod
    def get_subtitle_language(uri):
        if uri.path.endswith('.srt'):
            last = uri.path.rfind('.')
            prev = last
            for i in range(last, -1, -1):
                prev = uri.path.find('.', i)
                if prev != last:
                    break

            len_ = last - prev
            if 2 <= len_ <= 6:  # TODO: Validate lang
                return uri.path[prev + 1:last]
        return None

    @staticmethod
    def find_uri_in_scope(context, scope, uri):
        tree_uri = DocumentFile.from_tree_uri(context, scope)
        trail_scope = get_trail_from_uri(scope)
        trail_video = get_trail_from_uri(uri)

        for i in range(len(trail_video)):
            if i < len(trail_scope):
                if trail_scope[i] != trail_video[i]:
                    break
            else:
                tree_uri = tree_uri.find_file(trail_video[i])
                if tree_uri is None:
                    break

            if i + 1 == len(trail_video):
                return tree_uri
        return None

    @staticmethod
    def find_doc_in_scope(scope, doc):
        for file in scope.listdir():
            if file.is_directory():
                ret = find_doc_in_scope(file, doc)
                if ret is not None:
                    return ret
            else:
                #if doc.length() == file.length() and doc.last_modified() == file.last_modified() and doc.name == file.name:  # lastModified is zero when opened from Solid Explorer
                doc_name = doc.name
                file_name = file.name
                if (doc_name is None or file_name is None):
                    continue

                if doc.length() == file.length() and doc_name == file_name:
                    return file
        return None

    @staticmethod
    def get_trail_path_from_uri(uri):
        path = uri.path
        array = path.split(':')
        if len(array) > 1:
            return array[-1]
        else:
            return path

    @staticmethod
    def get_trail_from_uri(uri):
        if 'org.courville.nova.provider' == urlparse(uri).netloc and 'content' == urlparse(uri).scheme:
            path = uri.path
            if path.startswith('/external_files/'):
                return (path[len('/external_files/'):] + '').split('/')
            else:
                return get_trail_path_from_uri(uri).split('/')
        return get_trail_path_from_uri(uri).split('/')

    @staticmethod
    def file_base_name(name):
        if '.' in name:
            return name[:name.rfind('.')]
        return name

    @staticmethod
    def find_subtitle(video, dir=None):
        video_name = os.path.splitext(os.path.basename(video.name))[0]
        candidates = []

        for file in (dir or video).listdir():
            if not file.is_file() and file.name.startswith('.'):
                continue
            if is_video_file(file) or is_subtitle_file(file):
                candidates.append(file)

        if len(candidates) == 1:
            return candidates[0]
        elif len(candidates) > 1:
            for candidate in candidates:
                if candidate.name.startswith(video_name + '.'):
                    return candidate

    @staticmethod
    def find_next(video, dir=None):
        files = (dir or video).listdir()
        files.sort(key=lambda file: os.path.basename(file.name).lower())

        match_found = False

        for file in files:
            if file.name == os.path.basename(video.name) and not match_found:
                match_found = True
            elif match_found:
                if is_video_file(file):
                    return file

    @staticmethod
    def is_video_file(file):
        return file.is_file() and file.mime_type.startswith('video/')

    @staticmethod
    def is_subtitle_file(file):
        return file.is_file() and (file.name.endswith('.srt') or file.name.endswith('.ssa') or file.name.endswith('.ass') or file.name.endswith('.vtt') or file.name.endswith('.ttml'))

    @staticmethod
    def clear_cache(context):
        try:
            for file in context.cache_dir.listdir():
                if file.is_file():
                    file.delete()
        except Exception as e:
            print(str(e))

    @staticmethod
    def convert_to_utf(context, subtitle_uri):
        try:
            detector = CharsetDetector()
            buffered_input_stream = open(subtitle_uri, 'rb')
            detector.text = buffered_input_stream.read().decode('utf-8', errors='replace')
            charset_match = detector.detect()

            if not charset_match.name == 'UTF-8':
                filename = subtitle_uri.path
                filename = filename[filename.rfind('/') + 1:]
                file_path = os.path.join(context.cache_dir, filename)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(charset_match.text.decode('utf-16le'))
                return Uri.fromfile(file)

        except Exception as e:
            print(str(e))
