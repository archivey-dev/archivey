import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.CRC32;

import org.apache.commons.compress.archivers.*;
import org.apache.commons.compress.archivers.ar.ArArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarFile;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.compressors.CompressorStreamFactory;

/**
 * Lists every file named on stdin with Commons Compress, one JSON object per line: the
 * stream API, the file API where Commons Compress has one (ZIP, 7z, TAR), and a
 * compressor with any archive inside it. Each entry has its name, kind, declared size,
 * bytes read and CRC-32, or the error. scripts/gen_commons_compress_expected.py reads
 * the output; its docstring says how to build and run this.
 */
public class CcList {
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    static String err(Throwable t) {
        String m = t.getMessage();
        if (m != null && m.length() > 160) m = m.substring(0, 160);
        return q(t.getClass().getSimpleName() + ": " + m);
    }

    static String kind(ArchiveEntry e) {
        if (e instanceof TarArchiveEntry) {
            TarArchiveEntry t = (TarArchiveEntry) e;
            if (t.isSymbolicLink()) return "symlink";
            if (t.isLink()) return "hardlink";
            if (t.isDirectory()) return "dir";
            if (t.isFile()) return "file";
            return "other";
        }
        if (e instanceof ZipArchiveEntry) {
            ZipArchiveEntry z = (ZipArchiveEntry) e;
            if (z.isUnixSymlink()) return "symlink";
            return z.isDirectory() ? "dir" : "file";
        }
        if (e instanceof CpioArchiveEntry) {
            CpioArchiveEntry c = (CpioArchiveEntry) e;
            if (c.isSymbolicLink()) return "symlink";
            if (c.isDirectory()) return "dir";
            if (c.isRegularFile()) return "file";
            return "other";
        }
        if (e instanceof SevenZArchiveEntry) {
            SevenZArchiveEntry s = (SevenZArchiveEntry) e;
            return s.isDirectory() ? "dir" : (s.isAntiItem() ? "anti" : "file");
        }
        return e.isDirectory() ? "dir" : "file";
    }

    /** Reads a stream to the end; returns {size, crc}. */
    static long[] drain(InputStream in) throws IOException {
        CRC32 crc = new CRC32();
        byte[] buf = new byte[65536];
        long n = 0;
        int r;
        while ((r = in.read(buf)) > 0) {
            crc.update(buf, 0, r);
            n += r;
            if (n > (1L << 31)) throw new IOException("output over 2 GiB, stopped");
        }
        return new long[] {n, crc.getValue()};
    }

    static String entry(ArchiveEntry e, InputStream data, boolean canRead) {
        StringBuilder b = new StringBuilder("{\"name\":").append(q(e.getName()));
        b.append(",\"kind\":").append(q(kind(e)));
        b.append(",\"size\":").append(e.getSize());
        if (e instanceof TarArchiveEntry && ((TarArchiveEntry) e).getLinkName() != null
                && !((TarArchiveEntry) e).getLinkName().isEmpty())
            b.append(",\"link\":").append(q(((TarArchiveEntry) e).getLinkName()));
        if (!canRead) return b.append(",\"read\":\"unsupported\"}").toString();
        if (data != null && !e.isDirectory()) {
            try {
                long[] r = drain(data);
                b.append(",\"read\":").append(r[0]).append(",\"crc\":").append(r[1]);
            } catch (Throwable t) {
                b.append(",\"error\":").append(err(t));
            }
        }
        return b.append("}").toString();
    }

    static String streamMode(Path p) {
        List<String> out = new ArrayList<>();
        String fmt = null;
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(p))) {
            fmt = ArchiveStreamFactory.detect(raw);
            try (ArchiveInputStream<?> ais = ArchiveStreamFactory.DEFAULT.createArchiveInputStream(fmt, raw)) {
                ArchiveEntry e;
                while ((e = ais.getNextEntry()) != null) {
                    out.add(entry(e, ais, ais.canReadEntryData(e)));
                    if (out.size() > 100000) throw new IOException("over 100000 entries, stopped");
                }
                return "{\"format\":" + q(fmt) + ",\"entries\":[" + String.join(",", out) + "]}";
            }
        } catch (Throwable t) {
            return "{\"format\":" + q(fmt) + ",\"entries\":[" + String.join(",", out) + "],\"error\":" + err(t) + "}";
        }
    }

    static String fileMode(Path p, String fmt) {
        List<String> out = new ArrayList<>();
        try {
            if ("zip".equals(fmt) || "jar".equals(fmt)) {
                try (ZipFile z = ZipFile.builder().setPath(p).get()) {
                    for (ZipArchiveEntry e : Collections.list(z.getEntries())) {
                        boolean ok = z.canReadEntryData(e);
                        InputStream in = null;
                        String s;
                        try {
                            if (ok) in = z.getInputStream(e);
                            s = entry(e, in, ok);
                        } catch (Throwable t) {
                            s = "{\"name\":" + q(e.getName()) + ",\"error\":" + err(t) + "}";
                        }
                        out.add(s);
                        if (in != null) in.close();
                    }
                }
            } else if ("7z".equals(fmt)) {
                try (SevenZFile z = SevenZFile.builder().setPath(p).setPassword("foo".toCharArray()).get()) {
                    SevenZArchiveEntry e;
                    while ((e = z.getNextEntry()) != null) {
                        out.add(entry(e, e.hasStream() ? new InputStream() {
                            public int read() throws IOException { return z.read(); }
                            public int read(byte[] b, int o, int l) throws IOException { return z.read(b, o, l); }
                        } : null, true));
                    }
                }
            } else if ("tar".equals(fmt)) {
                try (TarFile t = new TarFile(p)) {
                    for (TarArchiveEntry e : t.getEntries()) {
                        try (InputStream in = t.getInputStream(e)) {
                            out.add(entry(e, in, true));
                        }
                    }
                }
            } else {
                return null;
            }
            return "{\"entries\":[" + String.join(",", out) + "]}";
        } catch (Throwable t) {
            return "{\"entries\":[" + String.join(",", out) + "],\"error\":" + err(t) + "}";
        }
    }

    static String compressor(Path p) {
        try (InputStream raw = new BufferedInputStream(Files.newInputStream(p))) {
            String fmt = CompressorStreamFactory.detect(raw);
            try (InputStream in = new BufferedInputStream(new CompressorStreamFactory(true).createCompressorInputStream(fmt, raw))) {
                String inner = null;
                try {
                    in.mark(1 << 16);
                    String afmt = ArchiveStreamFactory.detect(in);
                    in.reset();
                    List<String> out = new ArrayList<>();
                    String ierr = null;
                    try {
                        ArchiveInputStream<?> ais = ArchiveStreamFactory.DEFAULT.createArchiveInputStream(afmt, in);
                        ArchiveEntry e;
                        while ((e = ais.getNextEntry()) != null) out.add(entry(e, ais, ais.canReadEntryData(e)));
                    } catch (Throwable t) {
                        ierr = err(t);
                    }
                    inner = "{\"format\":" + q(afmt) + ",\"entries\":[" + String.join(",", out) + "]" + (ierr != null ? ",\"error\":" + ierr : "") + "}";
                } catch (Throwable t) {
                    in.reset();
                }
                if (inner != null) return "{\"format\":" + q(fmt) + ",\"inner\":" + inner + "}";
                long[] r = drain(in);
                return "{\"format\":" + q(fmt) + ",\"read\":" + r[0] + ",\"crc\":" + r[1] + "}";
            } catch (Throwable t) {
                return "{\"format\":" + q(fmt) + ",\"error\":" + err(t) + "}";
            }
        } catch (Throwable t) {
            return null;
        }
    }

    public static void main(String[] args) throws IOException {
        BufferedReader names = new BufferedReader(new InputStreamReader(System.in));
        String line;
        PrintStream o = new PrintStream(new FileOutputStream(FileDescriptor.out), true, "UTF-8");
        while ((line = names.readLine()) != null) {
            Path p = Paths.get(line);
            StringBuilder b = new StringBuilder("{\"path\":").append(q(line));
            String s = streamMode(p);
            String fmt = null;
            if (!s.startsWith("{\"format\":null")) {
                int i = s.indexOf('"', 11);
                fmt = s.substring(11, i);
                b.append(",\"stream\":").append(s);
                String f = fileMode(p, fmt);
                if (f != null) b.append(",\"file\":").append(f);
            } else {
                String c = compressor(p);
                if (c != null) b.append(",\"compressor\":").append(c);
            }
            o.println(b.append("}"));
        }
    }
}
