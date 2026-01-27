#!/usr/bin/env python3
"""
Even G2 Firmware Extraction and Analysis Tool

This tool extracts and analyzes DFU firmware packages from the Even Realities app.
Supports analysis of bootloader, softdevice, and application firmware components.
"""

import os
import sys
import json
import zipfile
import argparse
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass
class FirmwareComponent:
    """Represents a firmware component"""
    name: str
    bin_file: str
    dat_file: str
    bin_path: Optional[Path] = None
    dat_path: Optional[Path] = None

    @property
    def bin_size(self) -> int:
        """Get size of binary file in bytes"""
        if self.bin_path and self.bin_path.exists():
            return self.bin_path.stat().st_size
        return 0

    @property
    def dat_size(self) -> int:
        """Get size of metadata file in bytes"""
        if self.dat_path and self.dat_path.exists():
            return self.dat_path.stat().st_size
        return 0

    def calculate_checksums(self) -> Dict[str, str]:
        """Calculate MD5 and SHA256 checksums"""
        checksums = {}

        for file_path, prefix in [(self.bin_path, 'bin'), (self.dat_path, 'dat')]:
            if not file_path or not file_path.exists():
                continue

            md5 = hashlib.md5()
            sha256 = hashlib.sha256()

            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)

            checksums[f'{prefix}_md5'] = md5.hexdigest()
            checksums[f'{prefix}_sha256'] = sha256.hexdigest()

        return checksums


class FirmwarePackage:
    """Handles DFU firmware package operations"""

    def __init__(self, package_path: Path):
        """Initialize with DFU package path"""
        self.package_path = Path(package_path)
        self.extract_dir = self.package_path.parent / f"{self.package_path.stem}_extracted"
        self.components: Dict[str, FirmwareComponent] = {}
        self.manifest: Dict = {}

    def extract(self, force: bool = False) -> bool:
        """Extract firmware package contents"""
        if not self.package_path.exists():
            print(f"Error: Package not found: {self.package_path}")
            return False

        if not zipfile.is_zipfile(self.package_path):
            print(f"Error: Not a valid ZIP file: {self.package_path}")
            return False

        if self.extract_dir.exists() and not force:
            print(f"Extract directory already exists: {self.extract_dir}")
            print("Use --force to overwrite")
            return False

        try:
            print(f"Extracting firmware package: {self.package_path}")
            self.extract_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(self.package_path, 'r') as zf:
                zf.extractall(self.extract_dir)

            print(f"Extracted to: {self.extract_dir}")

            # Parse manifest
            manifest_path = self.extract_dir / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path, 'r') as f:
                    self.manifest = json.load(f)
                    self._load_components()

            return True

        except Exception as e:
            print(f"Error during extraction: {e}")
            return False

    def _load_components(self):
        """Load firmware components from manifest"""
        if 'manifest' not in self.manifest:
            return

        for component_name, component_info in self.manifest['manifest'].items():
            if not isinstance(component_info, dict):
                continue

            bin_file = component_info.get('bin_file')
            dat_file = component_info.get('dat_file')

            if not bin_file:
                continue

            component = FirmwareComponent(
                name=component_name,
                bin_file=bin_file,
                dat_file=dat_file or '',
                bin_path=self.extract_dir / bin_file,
                dat_path=self.extract_dir / dat_file if dat_file else None
            )

            self.components[component_name] = component

    def analyze(self) -> Dict:
        """Analyze firmware components"""
        if not self.components:
            print("No components found. Extract package first.")
            return {}

        analysis = {
            'package': self.package_path.name,
            'extract_dir': str(self.extract_dir),
            'components': {}
        }

        for name, component in self.components.items():
            print(f"\nAnalyzing {name}...")

            component_info = {
                'bin_file': component.bin_file,
                'bin_size': component.bin_size,
                'dat_file': component.dat_file,
                'dat_size': component.dat_size,
            }

            # Add checksums
            checksums = component.calculate_checksums()
            component_info.update(checksums)

            # Analyze binary header
            if component.bin_path and component.bin_path.exists():
                header = self._analyze_binary_header(component.bin_path)
                component_info['binary_analysis'] = header

            analysis['components'][name] = component_info

        return analysis

    @staticmethod
    def _analyze_binary_header(bin_path: Path) -> Dict:
        """Analyze binary file header"""
        try:
            with open(bin_path, 'rb') as f:
                # Read first 32 bytes (ARM vector table)
                header = f.read(32)

            analysis = {
                'format': 'binary',
                'architecture': 'ARM Cortex-M4',
                'endianness': 'little-endian',
            }

            if len(header) >= 4:
                # First 32-bit value is typically stack pointer
                sp = int.from_bytes(header[0:4], 'little')
                analysis['initial_sp'] = f"0x{sp:08x}"

                # Second 32-bit value is reset handler
                reset_handler = int.from_bytes(header[4:8], 'little')
                analysis['reset_handler'] = f"0x{reset_handler:08x}"

                # Check for ARM magic markers
                if header[0:4] == b'\x00\x00\x00\x00':
                    analysis['note'] = 'Padding bytes detected at start'

            return analysis

        except Exception as e:
            return {'error': str(e)}

    def print_summary(self, analysis: Dict):
        """Print analysis summary"""
        print("\n" + "=" * 70)
        print(f"Firmware Package Analysis: {analysis['package']}")
        print("=" * 70)

        for component_name, component_info in analysis.get('components', {}).items():
            print(f"\n{component_name.upper()}")
            print("-" * 50)
            print(f"  Binary file: {component_info['bin_file']} ({component_info['bin_size']} bytes)")

            if component_info['dat_file']:
                print(f"  Metadata:    {component_info['dat_file']} ({component_info['dat_size']} bytes)")

            print(f"  Binary MD5:  {component_info.get('bin_md5', 'N/A')}")
            print(f"  Binary SHA256: {component_info.get('bin_sha256', 'N/A')[:16]}...")

            if component_info.get('dat_md5'):
                print(f"  Meta MD5:    {component_info['dat_md5']}")

            if 'binary_analysis' in component_info:
                ba = component_info['binary_analysis']
                print(f"  Architecture: {ba.get('architecture', 'Unknown')}")
                print(f"  Initial SP:   {ba.get('initial_sp', 'Unknown')}")
                print(f"  Reset Handle: {ba.get('reset_handler', 'Unknown')}")

    def save_analysis(self, output_path: Path):
        """Save analysis to JSON file"""
        analysis = self.analyze()

        with open(output_path, 'w') as f:
            json.dump(analysis, f, indent=2)

        print(f"Analysis saved to: {output_path}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Extract and analyze Even G2 firmware packages'
    )
    parser.add_argument(
        'package',
        type=Path,
        help='Path to DFU firmware package (.zip file)'
    )
    parser.add_argument(
        '-e', '--extract',
        action='store_true',
        help='Extract firmware package'
    )
    parser.add_argument(
        '-a', '--analyze',
        action='store_true',
        help='Analyze firmware components'
    )
    parser.add_argument(
        '-f', '--force',
        action='store_true',
        help='Force overwrite existing extraction'
    )
    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Save analysis to JSON file'
    )

    args = parser.parse_args()

    # Create package handler
    package = FirmwarePackage(args.package)

    # Extract if requested
    if args.extract:
        if not package.extract(force=args.force):
            sys.exit(1)

    # Analyze if requested (or by default)
    if args.analyze or args.extract:
        analysis = package.analyze()
        package.print_summary(analysis)

        if args.output:
            package.save_analysis(args.output)


if __name__ == '__main__':
    main()
