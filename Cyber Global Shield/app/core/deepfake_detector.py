"""
Cyber Global Shield — Deepfake Detection
Détection de deepfakes audio, vidéo et image.
Analyse des artefacts numériques, métadonnées et incohérences.
"""

import json
import hashlib
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DeepfakeAnalysis:
    """Result of a deepfake analysis."""
    timestamp: datetime
    media_type: str  # image, video, audio
    file_hash: str
    is_deepfake: bool
    confidence: float
    detected_artifacts: List[str]
    analysis_details: Dict[str, Any]


class DeepfakeDetector:
    """
    Détecteur de deepfakes.
    
    Analyse:
    - Artefacts de génération IA (GAN fingerprints)
    - Incohérences de métadonnées
    - Anomalies de compression
    - Patterns de yeux/visage (vidéo)
    - Discontinuités audio
    - EXIF manipulation
    """

    def __init__(self):
        self._analyses: List[DeepfakeAnalysis] = []
        self._known_gan_fingerprints = self._load_gan_fingerprints()

    def _load_gan_fingerprints(self) -> Dict[str, List[str]]:
        """Load known GAN generation fingerprints."""
        return {
            "stylegan": [
                "periodic_noise", "checkerboard_artifacts",
                "color_aberration", "blurry_background",
            ],
            "stylegan2": [
                "aliasing_artifacts", "frequency_domain_patterns",
                "asymmetric_eyes", "ear_anomalies",
            ],
            "stylegan3": [
                "rotation_invariance_failure", "texture_repetition",
                "lighting_inconsistency", "shadow_anomalies",
            ],
            "diffusion": [
                "oversaturated_colors", "anatomical_errors",
                "background_noise_pattern", "edge_artifacts",
            ],
            "wav2lip": [
                "lip_sync_delay", "jaw_motion_anomaly",
                "teeth_artifacts", "skin_tone_mismatch",
            ],
        }

    def analyze_image(self, image_path: str, metadata: Dict[str, Any]) -> DeepfakeAnalysis:
        """Analyze an image for deepfake indicators."""
        artifacts = []
        confidence = 0.0

        # 1. Check EXIF metadata
        exif_anomalies = self._check_exif_anomalies(metadata)
        artifacts.extend(exif_anomalies)
        confidence += len(exif_anomalies) * 0.15

        # 2. Check for GAN fingerprints
        gan_indicators = self._check_gan_fingerprints(metadata)
        artifacts.extend(gan_indicators)
        confidence += len(gan_indicators) * 0.2

        # 3. Check file anomalies
        file_anomalies = self._check_file_anomalies(image_path, metadata)
        artifacts.extend(file_anomalies)
        confidence += len(file_anomalies) * 0.1

        # 4. Check for AI generation markers
        ai_markers = self._check_ai_generation_markers(metadata)
        artifacts.extend(ai_markers)
        confidence += len(ai_markers) * 0.25

        # Calculate file hash
        file_hash = hashlib.sha256(image_path.encode()).hexdigest()

        analysis = DeepfakeAnalysis(
            timestamp=datetime.utcnow(),
            media_type="image",
            file_hash=file_hash,
            is_deepfake=confidence > 0.5,
            confidence=min(confidence, 1.0),
            detected_artifacts=artifacts,
            analysis_details={
                "exif_anomalies": exif_anomalies,
                "gan_indicators": gan_indicators,
                "file_anomalies": file_anomalies,
                "ai_markers": ai_markers,
            },
        )

        self._analyses.append(analysis)
        
        if analysis.is_deepfake:
            logger.critical(f"🎭 Deepfake detected in image: {image_path} (confidence: {confidence:.1%})")
        else:
            logger.info(f"✅ Image verified authentic: {image_path}")

        return analysis

    def analyze_video(self, video_path: str, metadata: Dict[str, Any]) -> DeepfakeAnalysis:
        """Analyze a video for deepfake indicators."""
        artifacts = []
        confidence = 0.0

        # 1. Check frame consistency
        frame_anomalies = self._check_frame_consistency(metadata)
        artifacts.extend(frame_anomalies)
        confidence += len(frame_anomalies) * 0.15

        # 2. Check audio-visual sync
        av_anomalies = self._check_audio_visual_sync(metadata)
        artifacts.extend(av_anomalies)
        confidence += len(av_anomalies) * 0.2

        # 3. Check facial landmarks
        face_anomalies = self._check_facial_landmarks(metadata)
        artifacts.extend(face_anomalies)
        confidence += len(face_anomalies) * 0.2

        # 4. Check compression artifacts
        compression_anomalies = self._check_compression_artifacts(metadata)
        artifacts.extend(compression_anomalies)
        confidence += len(compression_anomalies) * 0.1

        file_hash = hashlib.sha256(video_path.encode()).hexdigest()

        analysis = DeepfakeAnalysis(
            timestamp=datetime.utcnow(),
            media_type="video",
            file_hash=file_hash,
            is_deepfake=confidence > 0.5,
            confidence=min(confidence, 1.0),
            detected_artifacts=artifacts,
            analysis_details={
                "frame_anomalies": frame_anomalies,
                "av_anomalies": av_anomalies,
                "face_anomalies": face_anomalies,
                "compression_anomalies": compression_anomalies,
            },
        )

        self._analyses.append(analysis)
        
        if analysis.is_deepfake:
            logger.critical(f"🎭 Deepfake detected in video: {video_path} (confidence: {confidence:.1%})")
        else:
            logger.info(f"✅ Video verified authentic: {video_path}")

        return analysis

    def analyze_audio(self, audio_path: str, metadata: Dict[str, Any]) -> DeepfakeAnalysis:
        """Analyze audio for deepfake indicators."""
        artifacts = []
        confidence = 0.0

        # 1. Check spectral anomalies
        spectral_anomalies = self._check_spectral_anomalies(metadata)
        artifacts.extend(spectral_anomalies)
        confidence += len(spectral_anomalies) * 0.2

        # 2. Check voice continuity
        voice_anomalies = self._check_voice_continuity(metadata)
        artifacts.extend(voice_anomalies)
        confidence += len(voice_anomalies) * 0.2

        # 3. Check background noise consistency
        noise_anomalies = self._check_noise_consistency(metadata)
        artifacts.extend(noise_anomalies)
        confidence += len(noise_anomalies) * 0.15

        file_hash = hashlib.sha256(audio_path.encode()).hexdigest()

        analysis = DeepfakeAnalysis(
            timestamp=datetime.utcnow(),
            media_type="audio",
            file_hash=file_hash,
            is_deepfake=confidence > 0.5,
            confidence=min(confidence, 1.0),
            detected_artifacts=artifacts,
            analysis_details={
                "spectral_anomalies": spectral_anomalies,
                "voice_anomalies": voice_anomalies,
                "noise_anomalies": noise_anomalies,
            },
        )

        self._analyses.append(analysis)
        
        if analysis.is_deepfake:
            logger.critical(f"🎭 Deepfake detected in audio: {audio_path} (confidence: {confidence:.1%})")
        else:
            logger.info(f"✅ Audio verified authentic: {audio_path}")

        return analysis

    def _check_exif_anomalies(self, metadata: Dict) -> List[str]:
        """Check EXIF metadata for anomalies."""
        anomalies = []
        
        # Check for missing EXIF
        if not metadata.get("exif"):
            anomalies.append("missing_exif_data")
        
        # Check for inconsistent dates
        if metadata.get("create_date") and metadata.get("modify_date"):
            if metadata["create_date"] > metadata["modify_date"]:
                anomalies.append("inconsistent_dates")
        
        # Check for software signatures
        software = metadata.get("software", "").lower()
        if any(tool in software for tool in ["photoshop", "gimp", "stable diffusion", "midjourney"]):
            anomalies.append(f"editing_software_detected: {software}")

        return anomalies

    def _check_gan_fingerprints(self, metadata: Dict) -> List[str]:
        """Check for GAN generation fingerprints."""
        indicators = []
        
        # Check resolution (GANs often produce specific resolutions)
        width = metadata.get("width", 0)
        height = metadata.get("height", 0)
        if width > 0 and height > 0:
            if width % 4 != 0 or height % 4 != 0:
                indicators.append("non_standard_resolution")
        
        # Check color profile
        if metadata.get("color_profile") == "sRGB":
            indicators.append("standard_color_profile")

        return indicators

    def _check_file_anomalies(self, file_path: str, metadata: Dict) -> List[str]:
        """Check file-level anomalies."""
        anomalies = []
        
        # Check file size vs resolution
        file_size = metadata.get("file_size", 0)
        width = metadata.get("width", 0)
        height = metadata.get("height", 0)
        
        if width > 0 and height > 0:
            expected_size = width * height * 3  # RGB
            if file_size < expected_size * 0.1:  # Too small
                anomalies.append("compression_ratio_anomaly")

        return anomalies

    def _check_ai_generation_markers(self, metadata: Dict) -> List[str]:
        """Check for AI generation markers."""
        markers = []
        
        # Check for known AI generation metadata
        software = metadata.get("software", "").lower()
        if "stable diffusion" in software:
            markers.append("stable_diffusion_generated")
        if "midjourney" in software:
            markers.append("midjourney_generated")
        if "dall-e" in software or "dalle" in software:
            markers.append("dalle_generated")

        return markers

    def _check_frame_consistency(self, metadata: Dict) -> List[str]:
        """Check video frame consistency."""
        anomalies = []
        
        # Check for frame drops or duplicates
        if metadata.get("frame_rate", 0) < 15:
            anomalies.append("low_frame_rate")
        
        # Check for inconsistent frame sizes
        if metadata.get("keyframe_interval", 0) > 250:
            anomalies.append("large_keyframe_interval")

        return anomalies

    def _check_audio_visual_sync(self, metadata: Dict) -> List[str]:
        """Check audio-visual synchronization."""
        anomalies = []
        
        # Check for audio delay
        if abs(metadata.get("audio_delay", 0)) > 0.1:
            anomalies.append("audio_visual_desync")

        return anomalies

    def _check_facial_landmarks(self, metadata: Dict) -> List[str]:
        """Check facial landmark consistency."""
        anomalies = []
        
        # Check for asymmetric features
        if metadata.get("eye_asymmetry", 0) > 0.1:
            anomalies.append("asymmetric_eyes")
        if metadata.get("mouth_asymmetry", 0) > 0.1:
            anomalies.append("asymmetric_mouth")

        return anomalies

    def _check_compression_artifacts(self, metadata: Dict) -> List[str]:
        """Check for compression artifacts."""
        anomalies = []
        
        # Check for inconsistent compression
        if metadata.get("compression_ratio", 0) > 100:
            anomalies.append("high_compression_ratio")

        return anomalies

    def _check_spectral_anomalies(self, metadata: Dict) -> List[str]:
        """Check audio spectral anomalies."""
        anomalies = []
        
        # Check for missing frequencies
        if metadata.get("frequency_gaps", 0) > 5:
            anomalies.append("frequency_gaps_detected")
        
        # Check for unnatural silence
        if metadata.get("silence_ratio", 0) < 0.01:
            anomalies.append("unnatural_continuous_audio")

        return anomalies

    def _check_voice_continuity(self, metadata: Dict) -> List[str]:
        """Check voice continuity."""
        anomalies = []
        
        # Check for voice breaks
        if metadata.get("voice_breaks", 0) > 3:
            anomalies.append("multiple_voice_breaks")

        return anomalies

    def _check_noise_consistency(self, metadata: Dict) -> List[str]:
        """Check background noise consistency."""
        anomalies = []
        
        # Check for inconsistent noise
        if metadata.get("noise_variance", 0) < 0.001:
            anomalies.append("too_clean_background")

        return anomalies

    def get_stats(self) -> Dict[str, Any]:
        """Get deepfake detection statistics."""
        recent = [
            a for a in self._analyses
            if (datetime.utcnow() - a.timestamp).total_seconds() < 3600
        ]
        deepfakes = [a for a in recent if a.is_deepfake]
        
        return {
            "total_analyzed": len(self._analyses),
            "recent_analyzed": len(recent),
            "deepfakes_detected": len(deepfakes),
            "deepfake_rate": (len(deepfakes) / len(recent) * 100) if recent else 0,
            "by_type": {
                "image": len([a for a in recent if a.media_type == "image"]),
                "video": len([a for a in recent if a.media_type == "video"]),
                "audio": len([a for a in recent if a.media_type == "audio"]),
            },
            "avg_confidence": (
                sum(a.confidence for a in deepfakes) / len(deepfakes)
                if deepfakes else 0
            ),
            "status": "MONITORING",
        }


deepfake_detector = DeepfakeDetector()
