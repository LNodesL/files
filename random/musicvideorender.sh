#!/usr/bin/env bash
set -euo pipefail

input_dir="."
output_file="outputVideo.mp4"
audio_crossfade="2.5"
image_fade="1.0"
fps="15"
width="1280"
height="720"
target_lufs="-16"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  -i, --input-dir DIR         Folder containing mp3 + images (default: current folder)
  -o, --output FILE           Output mp4 filename/path (default: outputVideo.mp4)
  --audio-crossfade SEC       Song overlap duration in seconds (default: 2.5)
  --image-fade SEC            Slideshow fade duration in seconds (default: 1.0)
  --fps N                     Video fps (default: 30)
  --target-lufs VALUE         Loudness target per track (default: -16)
  -h, --help                  Show help

Example:
  ./render.sh -i . -o final.mp4 --audio-crossfade 2.2 --image-fade 1.0
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--input-dir)
      input_dir="$2"
      shift 2
      ;;
    -o|--output)
      output_file="$2"
      shift 2
      ;;
    --audio-crossfade)
      audio_crossfade="$2"
      shift 2
      ;;
    --image-fade)
      image_fade="$2"
      shift 2
      ;;
    --fps)
      fps="$2"
      shift 2
      ;;
    --target-lufs)
      target_lufs="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "Error: ffmpeg is not installed or not on PATH." >&2
  exit 1
fi

if ! command -v ffprobe >/dev/null 2>&1; then
  echo "Error: ffprobe is not installed or not on PATH." >&2
  exit 1
fi

input_dir="$(cd "$input_dir" && pwd)"
if [[ "$output_file" != /* ]]; then
  output_file="$input_dir/$output_file"
fi

mp3_files=()
while IFS= read -r -d '' file; do
  mp3_files+=("$file")
done < <(find "$input_dir" -maxdepth 1 -type f -iname '*.mp3' -print0 | sort -z)

image_files=()
while IFS= read -r -d '' file; do
  image_files+=("$file")
done < <(find "$input_dir" -maxdepth 1 -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.webp' \) -print0 | sort -z)

num_tracks=${#mp3_files[@]}
num_images=${#image_files[@]}

if (( num_tracks == 0 )); then
  echo "Error: no mp3 files found in $input_dir" >&2
  exit 1
fi

if (( num_images == 0 )); then
  echo "Error: no image files found in $input_dir" >&2
  exit 1
fi

total_audio="0"
min_track="999999"

for track in "${mp3_files[@]}"; do
  dur=$(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$track" | tr -d '\r')
  if [[ -z "$dur" ]]; then
    echo "Error: could not read duration for $track" >&2
    exit 1
  fi
  total_audio=$(awk -v a="$total_audio" -v b="$dur" 'BEGIN{printf "%.6f", a+b}')
  min_track=$(awk -v a="$min_track" -v b="$dur" 'BEGIN{if (b<a) a=b; printf "%.6f", a}')
done

if (( num_tracks > 1 )); then
  max_crossfade=$(awk -v m="$min_track" 'BEGIN{v=m*0.20; if (v<0.35) v=0.35; printf "%.6f", v}')
  audio_crossfade=$(awk -v requested="$audio_crossfade" -v maxv="$max_crossfade" 'BEGIN{v=requested; if (v>maxv) v=maxv; if (v<0.2) v=0.2; printf "%.6f", v}')
  total_video_duration=$(awk -v t="$total_audio" -v n="$num_tracks" -v d="$audio_crossfade" 'BEGIN{v=t-((n-1)*d); if (v<1) v=t; printf "%.6f", v}')
else
  audio_crossfade="0"
  total_video_duration="$total_audio"
fi

if (( num_images == 1 )); then
  image_fade="0"
  per_image_duration="$total_video_duration"
  image_input_duration="$total_video_duration"
else
  max_image_fade=$(awk -v t="$total_video_duration" -v n="$num_images" 'BEGIN{v=t/(n*2); if (v<0.2) v=0.2; printf "%.6f", v}')
  image_fade=$(awk -v requested="$image_fade" -v maxv="$max_image_fade" 'BEGIN{v=requested; if (v>maxv) v=maxv; if (v<0.2) v=0.2; printf "%.6f", v}')
  per_image_duration=$(awk -v t="$total_video_duration" -v f="$image_fade" -v n="$num_images" 'BEGIN{v=(t-f)/n; if (v<=0) v=t/n; printf "%.6f", v}')
  image_input_duration=$(awk -v p="$per_image_duration" -v f="$image_fade" 'BEGIN{printf "%.6f", p+f}')
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
filter_file="$tmp_dir/filter_complex.txt"

{
  for i in "${!image_files[@]}"; do
    echo "[$i:v]scale=$width:$height:force_original_aspect_ratio=increase,crop=$width:$height,setsar=1,format=yuv420p[v$i];"
  done

  if (( num_images == 1 )); then
    echo "[v0]trim=duration=$total_video_duration,fps=$fps[vout];"
  else
    echo "[v0][v1]xfade=transition=fade:duration=$image_fade:offset=$per_image_duration[vx1];"
    for ((i=2; i<num_images; i++)); do
      offset=$(awk -v p="$per_image_duration" -v n="$i" 'BEGIN{printf "%.6f", p*n}')
      prev="vx$((i-1))"
      echo "[$prev][v$i]xfade=transition=fade:duration=$image_fade:offset=$offset[vx$i];"
    done
    echo "[vx$((num_images-1))]fps=$fps[vout];"
  fi

  audio_offset=$num_images
  for j in "${!mp3_files[@]}"; do
    idx=$((audio_offset + j))
    echo "[$idx:a]aformat=sample_fmts=fltp:sample_rates=48000:channel_layouts=stereo,loudnorm=I=$target_lufs:TP=-1.5:LRA=11,aresample=48000[an$j];"
  done

  if (( num_tracks == 1 )); then
    echo "[an0]alimiter=limit=0.95[aout]"
  else
    echo "[an0][an1]acrossfade=d=$audio_crossfade:c1=tri:c2=tri[ax1];"
    for ((j=2; j<num_tracks; j++)); do
      prev="ax$((j-1))"
      echo "[$prev][an$j]acrossfade=d=$audio_crossfade:c1=tri:c2=tri[ax$j];"
    done
    echo "[ax$((num_tracks-1))]alimiter=limit=0.95[aout]"
  fi
} > "$filter_file"

cmd=(ffmpeg -y)
for img in "${image_files[@]}"; do
  cmd+=(-loop 1 -t "$image_input_duration" -i "$img")
done
for track in "${mp3_files[@]}"; do
  cmd+=(-i "$track")
done

cmd+=(
  -/filter_complex "$filter_file"
  -map "[vout]"
  -map "[aout]"
  -c:v libx264
  -preset slow
  -crf 18
  -profile:v high
  -pix_fmt yuv420p
  -r "$fps"
  -c:a aac
  -b:a 320k
  -ar 48000
  -movflags +faststart
  -t "$total_video_duration"
  "$output_file"
)

echo "Tracks: $num_tracks | Images: $num_images"
echo "Total audio duration (pre-crossfade): $total_audio s"
echo "Audio crossfade: $audio_crossfade s"
echo "Image fade: $image_fade s"
echo "Target video duration: $total_video_duration s"
echo "Output: $output_file"

"${cmd[@]}"

echo "Done: $output_file"
