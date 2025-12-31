#!/usr/bin/env python3
"""Test iVCS decompilation on benchmarks."""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent import DecompilationAgent


def extract_text_section(obj_file: Path) -> bytes:
	"""Extract .text section from object file.

	For now, we'll use a simple heuristic to find the code section.
	In a real implementation, we'd parse the ELF header properly.
	"""
	# Read entire file
	data = obj_file.read_bytes()

	# Look for function signature pattern: push ebp; mov ebp, esp
	# This is 0x55 0x89 0xe5 in machine code
	pattern = b"\x55\x89\xe5"

	idx = data.find(pattern)
	if idx == -1:
		raise ValueError(f"Could not find function prologue in {obj_file}")

	# Extract from function start
	# For these simple benchmarks, we know the code ends with ret (0xc3)
	code_start = idx

	# Find the ret instruction
	ret_idx = data.find(b"\xc3", code_start)
	if ret_idx == -1:
		raise ValueError(f"Could not find ret instruction in {obj_file}")

	# Include the ret instruction
	return data[code_start : ret_idx + 1]


def test_benchmark(obj_file: Path, agent: DecompilationAgent) -> dict:
	"""Test decompilation on a single benchmark.

	Returns:
		Dict with test results
	"""
	print(f"\n{'=' * 60}")
	print(f"Testing: {obj_file.name}")
	print("=" * 60)

	# Extract code section
	try:
		binary = extract_text_section(obj_file)
		print(f"Code size: {len(binary)} bytes")
		print(f"Hex: {binary.hex()}")
	except Exception as e:
		print(f"❌ Failed to extract code: {e}")
		return {
			"name": obj_file.stem,
			"status": "EXTRACT_ERROR",
			"error": str(e),
		}

	# Decompile
	try:
		result = agent.decompile(
			binary,
			max_iterations=2,
			base_address=0x00000000,
		)

		# Print results
		print(f"\nIterations: {result.iterations}")

		if result.success:
			print("✅ SUCCESS - Perfect match!")
			print("\nGenerated C code:")
			print(result.c_code)
			return {
				"name": obj_file.stem,
				"status": "SUCCESS",
				"iterations": result.iterations,
				"match": 100.0,
				"code": result.c_code,
			}
		else:
			if result.verification:
				match_pct = result.verification.match_percentage
				compiled = result.verification.compilation_result.success

				if not compiled:
					print("❌ COMPILATION ERROR")
					print("\nErrors:")
					print(result.verification.compilation_result.stderr)
					status = "COMPILE_ERROR"
				else:
					print(f"⚠️  PARTIAL - {match_pct:.1f}% match")
					status = "PARTIAL"

				print("\nGenerated C code:")
				print(result.c_code)

				return {
					"name": obj_file.stem,
					"status": status,
					"iterations": result.iterations,
					"match": match_pct if compiled else 0.0,
					"code": result.c_code,
					"error": result.error,
				}
			else:
				print(f"❌ FAILED - {result.error}")
				return {
					"name": obj_file.stem,
					"status": "FAILED",
					"error": result.error,
				}

	except Exception as e:
		print(f"❌ EXCEPTION - {e}")
		import traceback

		traceback.print_exc()
		return {
			"name": obj_file.stem,
			"status": "EXCEPTION",
			"error": str(e),
		}


def main():
	"""Run all benchmark tests."""
	benchmarks_dir = Path(__file__).parent

	# Find all .o files
	obj_files = sorted(benchmarks_dir.glob("*.o"))

	if not obj_files:
		print("No benchmark object files found!")
		print("Run ./compile.sh first")
		sys.exit(1)

	print(f"Found {len(obj_files)} benchmarks")

	# Create agent
	agent = DecompilationAgent(
		model="qwen/qwen3-4b-2507",
		api_base="http://127.0.0.1:1234/v1",
		max_retries=3,
	)

	# Run tests
	results = []
	for obj_file in obj_files:
		result = test_benchmark(obj_file, agent)
		results.append(result)

	# Summary
	print(f"\n{'=' * 60}")
	print("SUMMARY")
	print("=" * 60)

	success_count = sum(1 for r in results if r["status"] == "SUCCESS")
	partial_count = sum(1 for r in results if r["status"] == "PARTIAL")
	failed_count = len(results) - success_count - partial_count

	for result in results:
		status = result["status"]
		name = result["name"]

		if status == "SUCCESS":
			print(f"✅ {name:<30} 100.0% ({result['iterations']} iterations)")
		elif status == "PARTIAL":
			match = result.get("match", 0.0)
			print(f"⚠️  {name:<30} {match:>5.1f}% ({result['iterations']} iterations)")
		else:
			print(f"❌ {name:<30} {status}")

	print()
	print(f"Success: {success_count}/{len(results)}")
	print(f"Partial: {partial_count}/{len(results)}")
	print(f"Failed:  {failed_count}/{len(results)}")

	# Return non-zero if any failures
	sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
	main()
