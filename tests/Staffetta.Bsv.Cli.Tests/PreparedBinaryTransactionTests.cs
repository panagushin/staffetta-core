using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli.Tests;

[TestClass]
public sealed class PreparedBinaryTransactionTests
{
    [TestMethod]
    public async Task MultiMegabyteTransactionIsValidatedAndReplayedInBoundedChunks()
    {
        const int scriptLength = 3 * 1024 * 1024;
        var path = await TransactionFixture.WriteTempAsync(scriptLength);
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            Assert.AreEqual((ulong)new FileInfo(path).Length, prepared.Summary.SerializedLength);
            Assert.AreEqual(1UL, prepared.Summary.InputCount);
            Assert.AreEqual(1UL, prepared.Summary.OutputCount);

            var buffer = new byte[PreparedBinaryTransaction.BufferLength];
            using var firstHash = System.Security.Cryptography.IncrementalHash.CreateHash(
                System.Security.Cryptography.HashAlgorithmName.SHA256);
            ulong readTotal = 0;
            int read;
            while ((read = await prepared.ReadAsync(buffer, CancellationToken.None)) != 0)
            {
                firstHash.AppendData(buffer.AsSpan(0, read));
                readTotal += (ulong)read;
            }

            Span<byte> first = stackalloc byte[Hash256.Length];
            Assert.IsTrue(firstHash.TryGetHashAndReset(first, out var written));
            Assert.AreEqual(Hash256.Length, written);
            Span<byte> second = stackalloc byte[Hash256.Length];
            System.Security.Cryptography.SHA256.HashData(first, second);
            Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(second, out var replayedId));
            Assert.AreEqual(prepared.TransactionId, replayedId);
            Assert.AreEqual(prepared.Length, readTotal);
            Assert.AreEqual(PreparedBinaryTransaction.BufferLength, prepared.MaximumReadRequestLength);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task TrailingAndIncompleteTransactionsAreRejected()
    {
        var trailing = await TransactionFixture.WriteTempAsync(trailing: new byte[] { 0x00 });
        var incomplete = Path.Combine(Path.GetTempPath(), $"staffetta-cli-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(incomplete, TransactionFixture.CreateMinimal()[..^1]);
        try
        {
            await Assert.ThrowsAsync<TransactionInputException>(async () =>
                await PreparedBinaryTransaction.OpenAndValidateAsync(trailing, CancellationToken.None));
            await Assert.ThrowsAsync<TransactionInputException>(async () =>
                await PreparedBinaryTransaction.OpenAndValidateAsync(incomplete, CancellationToken.None));
        }
        finally
        {
            File.Delete(trailing);
            File.Delete(incomplete);
        }
    }

    [TestMethod]
    public async Task MonetaryInvalidTransactionsAreRejectedAfterStructuralParsing()
    {
        var negative = await TransactionFixture.WriteTempAsync(outputValueSatoshis: -1);
        var tooLarge = await TransactionFixture.WriteTempAsync(
            outputValueSatoshis: 2_100_000_000_000_001);
        try
        {
            var negativeError = await Assert.ThrowsAsync<TransactionInputException>(async () =>
                await PreparedBinaryTransaction.OpenAndValidateAsync(negative, CancellationToken.None));
            StringAssert.Contains(negativeError.Message, "NegativeOutput");
            var tooLargeError = await Assert.ThrowsAsync<TransactionInputException>(async () =>
                await PreparedBinaryTransaction.OpenAndValidateAsync(tooLarge, CancellationToken.None));
            StringAssert.Contains(tooLargeError.Message, "OutputExceedsMaximum");
        }
        finally
        {
            File.Delete(negative);
            File.Delete(tooLarge);
        }
    }

    [TestMethod]
    public async Task ReplayReadHonorsCancellationAndDisposeIsIdempotent()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await prepared.ReadAsync(new byte[16], cancellation.Token));

            await prepared.DisposeAsync();
            await prepared.DisposeAsync();
            await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
                await prepared.ReadAsync(new byte[16], CancellationToken.None));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task TransactionEndingExactlyAtBufferBoundaryStillRejectsNextTrailingByte()
    {
        const int scriptLengthForExactBuffer = PreparedBinaryTransaction.BufferLength - 62;
        var path = await TransactionFixture.WriteTempAsync(
            scriptLengthForExactBuffer,
            new byte[] { 0x00 });
        try
        {
            Assert.AreEqual(PreparedBinaryTransaction.BufferLength + 1, new FileInfo(path).Length);
            await Assert.ThrowsAsync<TransactionInputException>(async () =>
                await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
