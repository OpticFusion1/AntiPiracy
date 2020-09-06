package net.directleaks.antireleak.attr;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassWriter;

public class SourceDebugExtension extends Attribute {
	private String message;

    public SourceDebugExtension(String message) {
        super("SourceDebugExtension");
        this.message = message;
    }

    @Override
    public boolean isUnknown() {
        return false;
    }

    @Override
    protected ByteVector write(ClassWriter cw, byte[] code, int len, int maxStack, int maxLocals) {
        return new ByteVector().putUTF8(this.message);
    }
}