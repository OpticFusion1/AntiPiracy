package net.directleaks.antireleak;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.ListIterator;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InnerClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import net.directleaks.antireleak.attr.SourceDebugExtension;

public class Injector implements Opcodes {
	private static String bootstrapMethodName;
	private static String xorMethodName;
	private static String fakeBooleanName;
	private static String statusCheckName;
	private static String java6MethodName;
	private static String APICheckMethodName;

	@SuppressWarnings("serial")
	private static final List<String> PLACEHOLDERS = new ArrayList<String>() {
		{
			this.add("%%__USER__%%");
			this.add("%%__NONCE__%%");
			this.add("%%__RESOURCE__%%");
			this.add("%%__RANDOM__%%");
			this.add("%%__MD5ID__%%");
			this.add("%%__SHA-256ID__%%");
			this.add("%%__SHA-1ID__%%");
			this.add("%%__TIME__%%");
			this.add("%%__XORID__%%");
			this.add("%%__USER2__%%");
			this.add("%%__DATE__%%");
		}
	};
	private File file;
	private String link;
	private Long currentTime = null;
	private Info info;

	public Injector(File file, String userId, String resourceId, String link) {
		this.file = file;
		this.info = new Info(userId, resourceId);
		this.link = link;
	}

	@SuppressWarnings("unused")
	public InputStream getInjectedFile() throws Throwable {
		bootstrapMethodName = Generator.returnString();
		xorMethodName = Generator.returnString();
		fakeBooleanName = Generator.returnString();
		statusCheckName = Generator.returnString();
		java6MethodName = Generator.returnString();
		APICheckMethodName = Generator.returnString();

		InputStream input;
		ZipFile zipFile = new ZipFile(this.file);
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ZipOutputStream zos = new ZipOutputStream(output);
		while (entries.hasMoreElements()) {
			boolean modified = false;
			boolean mainClass = false;
			boolean addId = false;
			ZipEntry entry = entries.nextElement();
			ClassNode classNode = new ClassNode();
			if (this.currentTime == null) {
				this.currentTime = entry.getTime();
			}
			if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
				ClassReader classReader = new ClassReader(zipFile.getInputStream(entry));
				classReader.accept(classNode, 0);
				if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin")
						|| classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
					mainClass = true;
					modified = true;
					FieldNode fakeBoolean = new FieldNode(9, fakeBooleanName, "I", null, null);
					FieldNode statusCheck = new FieldNode(9, statusCheckName, "Ljava/lang/String;", null, "");
					if (classNode.version >= 51) {
						classNode.fields.add(fakeBoolean);
						classNode.fields.add(statusCheck);
						classNode.methods.add(Injector.makeXorMethod());
						classNode.methods.add(Injector.makeBootstrapMethod(classNode.name, this.link,
								this.info.getResourceId(), this.info.getUserId(), generateNonceId()));
						classNode.methods.add(Injector.makeAPICheck());
						for (MethodNode method : classNode.methods) {
							if (method.name.equals(bootstrapMethodName)) {
								ListIterator<AbstractInsnNode> insns = method.instructions.iterator();
								while (insns.hasNext()) {
									Object cst;
									AbstractInsnNode insn = insns.next();
									if ((insn instanceof LdcInsnNode)
											&& ((cst = ((LdcInsnNode) insn).cst) instanceof String)
											&& Injector.containPlaceHolder((String) ((LdcInsnNode) insn).cst)) {
										((LdcInsnNode) insn).cst = Injector
												.replacePlaceholders((String) ((LdcInsnNode) insn).cst, this.info);
										modified = true;
									}
								}
							}
						}
						for (MethodNode method : classNode.methods) {
							InsnList copy = Injector.copyInsnList(method.instructions);
							int i = 0;
							while (i < copy.size()) {
								AbstractInsnNode insn = copy.get(i);
								if (insn instanceof LdcInsnNode) {
									Object cst = ((LdcInsnNode) insn).cst;
									if (cst instanceof String) {
										if (insn.getNext() instanceof MethodInsnNode
												&& ((String) (((LdcInsnNode) insn).cst))
														.contains("%%__ENCRYPTME__%%")) {
											if (!(cst instanceof String)
													|| !((String) cst).contains("%%__ENCRYPTME__%%"))
												continue;
											{
												((LdcInsnNode) insn).cst = Injector
														.xor(((String) ((LdcInsnNode) insn).cst)
																.replace("%%__ENCRYPTME__%%", ""));

												method.instructions.insert(insn, new MethodInsnNode(184, classNode.name,
														"\u0972", "(Ljava/lang/String;)Ljava/lang/String;", false));
											}
										}
									}
								}
								++i;
							}

							InsnList copy2 = Injector.copyInsnList(method.instructions);
							int j = 0;
							while (j < copy2.size()) {
								AbstractInsnNode insn = copy2.get(j);
								if (!(!(insn instanceof MethodInsnNode)
										|| ((MethodInsnNode) insn).owner.startsWith("java/lang/reflect")
										|| ((MethodInsnNode) insn).owner.startsWith("java/lang/Class")
										|| method.name.equals(bootstrapMethodName)
										|| method.name.equals(xorMethodName))) {
									Handle handle;
									Type type;
									boolean flag = false;
									InvokeDynamicInsnNode newInsn = null;
									if (insn.getOpcode() == INVOKESTATIC) {
										String opcode1 = String.valueOf((insn.getOpcode() / 100));
										String opcode2 = String.valueOf(((insn.getOpcode() / 10) % 10));
										String opcode3 = String.valueOf((insn.getOpcode() % 10));

										handle = new Handle(Opcodes.H_INVOKESTATIC, classNode.name, bootstrapMethodName,
												"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
												false);
										newInsn = new InvokeDynamicInsnNode(Generator.returnString(),
												((MethodInsnNode) insn).desc, handle, opcode1, opcode2, opcode3,
												((MethodInsnNode) insn).owner.replace("/", "."),
												((MethodInsnNode) insn).name, ((MethodInsnNode) insn).desc,
												Generator.returnString());
										method.instructions.set(insn, newInsn);
										flag = true;
									} else if (insn.getOpcode() == INVOKEVIRTUAL
											|| insn.getOpcode() == INVOKEINTERFACE) {
										String opcode1 = String.valueOf((insn.getOpcode() / 100));
										String opcode2 = String.valueOf(((insn.getOpcode() / 10) % 10));
										String opcode3 = String.valueOf((insn.getOpcode() % 10));

										handle = new Handle(Opcodes.H_INVOKESTATIC, classNode.name, bootstrapMethodName,
												"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
												false);
										newInsn = new InvokeDynamicInsnNode(Generator.returnString(),
												((MethodInsnNode) insn).desc.replace("(", "(Ljava/lang/Object;"),
												handle, opcode1, opcode2, opcode3,
												((MethodInsnNode) insn).owner.replace("/", "."),
												((MethodInsnNode) insn).name, ((MethodInsnNode) insn).desc,
												Generator.returnString());
										method.instructions.set(insn, newInsn);
										flag = true;
									}
									if (flag && (type = Type.getType(((MethodInsnNode) insn).desc)).getReturnType()
											.getSort() == 9) {
										method.instructions.insert((AbstractInsnNode) newInsn,
												new TypeInsnNode(192, type.getReturnType().getInternalName()));
									}
								}
								++j;
							}
							if (method.name.equals("onEnable")) {
								method.instructions.insert(
										new MethodInsnNode(184, classNode.name, APICheckMethodName, "()V", false));
							}
						}
					} else {
						MethodNode java6Method = null;
						for (MethodNode method : classNode.methods) {
							if ((method.name.equals("onLoad") && method.desc.equals("()V")
									|| method.name.equals("onEnable") && method.desc.equals("()V"))) {
								method.instructions
										.insert(new MethodInsnNode(184, classNode.name, java6MethodName, "()V", false));
								java6Method = Injector.makeJava6Method(classNode.name, this.link,
										this.info.getResourceId(), this.info.getUserId(), generateNonceId());
								break;
							}

						}
						if (java6Method != null) {
							classNode.methods.add(java6Method);
							classNode.methods.add(Injector.makeXorMethod());
						}
						for (MethodNode method : classNode.methods) {
							InsnList copy = Injector.copyInsnList(method.instructions);
							int i = 0;
							while (i < copy.size()) {
								Object cst;
								AbstractInsnNode insn = copy.get(i);
								if (!(insn instanceof LdcInsnNode)
										|| !((cst = ((LdcInsnNode) insn).cst) instanceof String)
										|| !((String) cst).contains("%%__ENCRYPTME__%%"))
									continue;
								{
									((LdcInsnNode) insn).cst = Injector
											.xor(((String) ((LdcInsnNode) insn).cst).replace("%%__ENCRYPTME__%%", ""));
									method.instructions.insert(insn, new MethodInsnNode(184, classNode.name, "\u0972",
											"(Ljava/lang/String;)Ljava/lang/String;", false));
								}
								++i;
							}
						}
					}

					if (classNode.attrs == null) {
						classNode.attrs = new ArrayList<Attribute>(1);
					}
					classNode.attrs.add(
							new SourceDebugExtension(Injector.xor(String.format("ID: %s", this.info.getUserId()))));
				}
				if (classNode.signature == null) {

				}

				for (MethodNode method : classNode.methods) {
					ListIterator<AbstractInsnNode> insns = method.instructions.iterator();
					while (insns.hasNext()) {
						Object cst;
						AbstractInsnNode insn = insns.next();
						if ((insn instanceof LdcInsnNode) && ((cst = ((LdcInsnNode) insn).cst) instanceof String)
								&& Injector.containPlaceHolder((String) ((LdcInsnNode) insn).cst)) {
							((LdcInsnNode) insn).cst = Injector.replacePlaceholders((String) ((LdcInsnNode) insn).cst,
									this.info);
							modified = true;
						}

					}
				}
				if (Injector.getRandom().nextInt(10) >= 5) {
					addId = true;
					modified = true;
				}
			}
			if (!modified) {
				input = zipFile.getInputStream(entry);
			} else {
				ClassWriter classWriter = new ClassWriter(0);
				classNode.accept(classWriter);
				if (mainClass) {
					classWriter.newUTF8("BLORG");
				} else if (addId) {
					if (Injector.getRandom().nextInt(10) >= 5) {
						classWriter.newUTF8("BL" + this.info.getUserId() + "ORG");
					} else {
						classWriter.newUTF8(
								"6683" + String.valueOf(Integer.valueOf(this.info.getUserId()) + 66837767) + "7767");
					}
				}
				input = new ByteArrayInputStream(classWriter.toByteArray());
			}
			ZipEntry newEntry = new ZipEntry(entry.getName());
			newEntry.setTime(this.currentTime);
			zos.putNextEntry(newEntry);
			Injector.writeToOut(zos, input);
		}

		zos.setComment("Website: https://infiniteleaks.org \nResource: https://infiniteleaks.org/resources/"
				+ this.info.getResourceId() + "\nUserID: " + this.info.getUserId());

		zos.close();
		zipFile.close();
		zipFile = null;
		zos = null;
		input = null;
		System.gc();
		return new ByteArrayInputStream(output.toByteArray());
	}

	private static MethodNode makeAPICheck() {
		MethodNode mv = new MethodNode(ACC_PUBLIC + ACC_STATIC, APICheckMethodName, "()V", null, null);

		Label l2 = new Label();
		mv.visitTryCatchBlock(l0, l1, l2, "java/lang/ClassNotFoundException");
		Label l3 = new Label();
		Label l4 = new Label();
		Label l5 = new Label();
		mv.visitTryCatchBlock(l3, l4, l5, "java/lang/ClassNotFoundException");
		Label l6 = new Label();
		Label l7 = new Label();
		Label l8 = new Label();
		mv.visitTryCatchBlock(l6, l7, l8, "java/io/IOException");
		mv.visitTryCatchBlock(l6, l7, l8, "org/bukkit/configuration/InvalidConfigurationException");
		Label l9 = new Label();
		mv.visitLabel(l9);
		mv.visitLineNumber(20, l9);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getServer", "()Lorg/bukkit/Server;", false);
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/Server", "getPluginManager",
				"()Lorg/bukkit/plugin/PluginManager;", true);
		mv.visitLdcInsn("DirectLeaks-API");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "getPlugin",
				"(Ljava/lang/String;)Lorg/bukkit/plugin/Plugin;", true);
		Label l10 = new Label();
		mv.visitJumpInsn(IFNONNULL, l10);
		Label l11 = new Label();
		mv.visitLabel(l11);
		mv.visitLineNumber(21, l11);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitLdcInsn("\u00a7c[DirectLeaks] The DirectLeaks-API is not installed!");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l12 = new Label();
		mv.visitLabel(l12);
		mv.visitLineNumber(22, l12);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l10);
		mv.visitLineNumber(24, l10);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getServer", "()Lorg/bukkit/Server;", false);
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/Server", "getPluginManager",
				"()Lorg/bukkit/plugin/PluginManager;", true);
		mv.visitLdcInsn("DirectLeaks-API");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "isPluginEnabled",
				"(Ljava/lang/String;)Z", true);
		Label l13 = new Label();
		mv.visitJumpInsn(IFNE, l13);
		Label l14 = new Label();
		mv.visitLabel(l14);
		mv.visitLineNumber(25, l14);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitLdcInsn("\u00a7c[DirectLeaks] The DirectLeaks-API has thrown an error!");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l15 = new Label();
		mv.visitLabel(l15);
		mv.visitLineNumber(26, l15);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l13);
		mv.visitLineNumber(28, l13);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitTypeInsn(NEW, "java/io/File");
		mv.visitInsn(DUP);
		mv.visitLdcInsn("plugins/DirectLeaks-API.jar");
		mv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
		mv.visitVarInsn(ASTORE, 2);
		Label l16 = new Label();
		mv.visitLabel(l16);
		mv.visitLineNumber(29, l16);
		mv.visitVarInsn(ALOAD, 2);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
		mv.visitJumpInsn(IFNE, l0);
		Label l17 = new Label();
		mv.visitLabel(l17);
		mv.visitLineNumber(30, l17);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitLdcInsn("\u00a7c[DirectLeaks] The DirectLeaks-API has to be named: 'DirectLeaks-API.jar'");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l18 = new Label();
		mv.visitLabel(l18);
		mv.visitLineNumber(31, l18);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l0);
		mv.visitLineNumber(35, l0);
		mv.visitFrame(Opcodes.F_FULL, 3, new Object[] { Opcodes.TOP, Opcodes.TOP, "java/io/File" }, 0, new Object[] {});
		mv.visitLdcInsn("de.xbrowniecodez.dlapi.Main");
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false);
		mv.visitInsn(POP);
		mv.visitLabel(l1);
		mv.visitLineNumber(36, l1);
		mv.visitJumpInsn(GOTO, l3);
		mv.visitLabel(l2);
		mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] { "java/lang/ClassNotFoundException" });
		mv.visitVarInsn(ASTORE, 3);
		Label l19 = new Label();
		mv.visitLabel(l19);
		mv.visitLineNumber(37, l19);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitLdcInsn("\u00a7c[DirectLeaks] DirectLeaks-API can't be initialized, contact DirectLeaks!");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l20 = new Label();
		mv.visitLabel(l20);
		mv.visitLineNumber(38, l20);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l3);
		mv.visitLineNumber(41, l3);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitLdcInsn("de.xbrowniecodez.dlapi.HostsCheck");
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false);
		mv.visitInsn(POP);
		mv.visitLabel(l4);
		mv.visitLineNumber(42, l4);
		Label l21 = new Label();
		mv.visitJumpInsn(GOTO, l21);
		mv.visitLabel(l5);
		mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] { "java/lang/ClassNotFoundException" });
		mv.visitVarInsn(ASTORE, 3);
		Label l22 = new Label();
		mv.visitLabel(l22);
		mv.visitLineNumber(43, l22);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitLdcInsn("\u00a7c[DirectLeaks] The DirectLeaks API is corrupted! Please redownload it.");
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l23 = new Label();
		mv.visitLabel(l23);
		mv.visitLineNumber(45, l23);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l21);
		mv.visitLineNumber(47, l21);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitTypeInsn(NEW, "org/bukkit/configuration/file/YamlConfiguration");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "org/bukkit/configuration/file/YamlConfiguration", "<init>", "()V", false);
		mv.visitVarInsn(ASTORE, 1);
		Label l24 = new Label();
		mv.visitLabel(l24);
		mv.visitLineNumber(48, l24);
		mv.visitTypeInsn(NEW, "java/io/File");
		mv.visitInsn(DUP);
		mv.visitLdcInsn("plugins/DirectLeaks-API/userId.yml");
		mv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
		mv.visitVarInsn(ASTORE, 0);
		Label l25 = new Label();
		mv.visitLabel(l25);
		mv.visitLineNumber(49, l25);
		mv.visitLdcInsn("%%__USER__%%");
		mv.visitVarInsn(ASTORE, 3);
		mv.visitLabel(l6);
		mv.visitLineNumber(51, l6);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitMethodInsn(INVOKEVIRTUAL, "org/bukkit/configuration/file/FileConfiguration", "load",
				"(Ljava/io/File;)V", false);
		mv.visitLabel(l7);
		mv.visitLineNumber(52, l7);
		Label l26 = new Label();
		mv.visitJumpInsn(GOTO, l26);
		mv.visitLabel(l8);
		mv.visitFrame(Opcodes.F_FULL, 4, new Object[] { "java/io/File",
				"org/bukkit/configuration/file/FileConfiguration", "java/io/File", "java/lang/String" }, 1,
				new Object[] { "java/lang/Exception" });
		mv.visitVarInsn(ASTORE, 4);
		Label l27 = new Label();
		mv.visitLabel(l27);
		mv.visitLineNumber(53, l27);
		mv.visitVarInsn(ALOAD, 4);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Exception", "printStackTrace", "()V", false);
		mv.visitLabel(l26);
		mv.visitLineNumber(55, l26);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitLdcInsn("DirectLeaks.userId");
		mv.visitMethodInsn(INVOKEVIRTUAL, "org/bukkit/configuration/file/FileConfiguration", "getString",
				"(Ljava/lang/String;)Ljava/lang/String;", false);
		mv.visitLdcInsn("USERID_HERE");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l28 = new Label();
		mv.visitJumpInsn(IFEQ, l28);
		Label l29 = new Label();
		mv.visitLabel(l29);
		mv.visitLineNumber(56, l29);
		mv.visitLdcInsn(
				"\u00a7c[DirectLeaks] Please enter your DirectLeaks UserID in the config of the DirectLeaks-API!");
		mv.visitVarInsn(ASTORE, 4);
		Label l30 = new Label();
		mv.visitLabel(l30);
		mv.visitLineNumber(57, l30);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitVarInsn(ALOAD, 4);
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l31 = new Label();
		mv.visitLabel(l31);
		mv.visitLineNumber(58, l31);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l28);
		mv.visitLineNumber(59, l28);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitLdcInsn("DirectLeaks.userId");
		mv.visitMethodInsn(INVOKEVIRTUAL, "org/bukkit/configuration/file/FileConfiguration", "getString",
				"(Ljava/lang/String;)Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 3);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l32 = new Label();
		mv.visitJumpInsn(IFNE, l32);
		Label l33 = new Label();
		mv.visitLabel(l33);
		mv.visitLineNumber(60, l33);
		mv.visitLdcInsn("\u00a7c[DirectLeaks] The plugin is not downloaded by you!");
		mv.visitVarInsn(ASTORE, 4);
		Label l34 = new Label();
		mv.visitLabel(l34);
		mv.visitLineNumber(61, l34);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitVarInsn(ALOAD, 4);
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l35 = new Label();
		mv.visitLabel(l35);
		mv.visitLineNumber(62, l35);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l32);
		mv.visitLineNumber(65, l32);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ALOAD, 3);
		mv.visitLdcInsn("%%__USER__%%");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l36 = new Label();
		mv.visitJumpInsn(IFNE, l36);
		Label l37 = new Label();
		mv.visitLabel(l37);
		mv.visitLineNumber(66, l37);
		mv.visitLdcInsn("\u00a7c[DirectLeaks-API] The Plugin corrupted! Please redownload it.");
		mv.visitVarInsn(ASTORE, 4);
		Label l38 = new Label();
		mv.visitLabel(l38);
		mv.visitLineNumber(67, l38);
		mv.visitMethodInsn(INVOKESTATIC, "org/bukkit/Bukkit", "getConsoleSender",
				"()Lorg/bukkit/command/ConsoleCommandSender;", false);
		mv.visitVarInsn(ALOAD, 4);
		mv.visitMethodInsn(INVOKEINTERFACE, "org/bukkit/command/ConsoleCommandSender", "sendMessage",
				"(Ljava/lang/String;)V", true);
		Label l39 = new Label();
		mv.visitLabel(l39);
		mv.visitLineNumber(68, l39);
		mv.visitTypeInsn(NEW, "java/lang/RuntimeException");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l36);
		mv.visitLineNumber(70, l36);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(RETURN);
		Label l40 = new Label();
		mv.visitLabel(l40);
		mv.visitLocalVariable("customConfigFile", "Ljava/io/File;", null, l25, l40, 0);
		mv.visitLocalVariable("customConfig", "Lorg/bukkit/configuration/file/FileConfiguration;", null, l24, l40, 1);
		mv.visitLocalVariable("file", "Ljava/io/File;", null, l16, l40, 2);
		mv.visitLocalVariable("e", "Ljava/lang/ClassNotFoundException;", null, l19, l3, 3);
		mv.visitLocalVariable("e", "Ljava/lang/ClassNotFoundException;", null, l22, l21, 3);
		mv.visitLocalVariable("areyouacock", "Ljava/lang/String;", null, l6, l40, 3);
		mv.visitLocalVariable("e", "Ljava/lang/Exception;", null, l27, l26, 4);
		mv.visitLocalVariable("entuid", "Ljava/lang/String;", null, l30, l28, 4);
		mv.visitLocalVariable("wronguid", "Ljava/lang/String;", null, l34, l32, 4);
		mv.visitLocalVariable("error", "Ljava/lang/String;", null, l38, l36, 4);
		mv.visitMaxs(3, 5);
		mv.visitEnd();
		return mv;
	}

	private static MethodNode makeBootstrapMethod(String className, String link, String resourceId, String userId,
			String nonceId) {
		MethodNode mv = new MethodNode(ACC_PRIVATE + ACC_STATIC + ACC_SYNTHETIC + ACC_BRIDGE, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				null, null);
		mv.visitCode();
		Label l0 = new Label();
		Label l1 = new Label();
		Label l2 = new Label();
		mv.visitTryCatchBlock(l0, l1, l2, "java/lang/Exception");
		Label l3 = new Label();
		Label l4 = new Label();
		Label l5 = new Label();
		mv.visitTryCatchBlock(l3, l4, l5, "java/lang/Throwable");
		Label l6 = new Label();
		Label l7 = new Label();
		Label l8 = new Label();
		mv.visitTryCatchBlock(l6, l7, l8, "java/lang/Throwable");
		Label l9 = new Label();
		Label l10 = new Label();
		Label l11 = new Label();
		mv.visitTryCatchBlock(l9, l10, l11, "java/lang/Throwable");
		Label l12 = new Label();
		Label l13 = new Label();
		Label l14 = new Label();
		mv.visitTryCatchBlock(l12, l13, l14, "java/lang/Throwable");
		Label l15 = new Label();
		Label l16 = new Label();
		Label l17 = new Label();
		mv.visitTryCatchBlock(l15, l16, l17, "java/lang/Throwable");
		Label l18 = new Label();
		Label l19 = new Label();
		Label l20 = new Label();
		mv.visitTryCatchBlock(l18, l19, l20, "java/lang/Throwable");
		Label l21 = new Label();
		Label l22 = new Label();
		Label l23 = new Label();
		mv.visitTryCatchBlock(l21, l22, l23, "java/lang/Exception");
		Label l24 = new Label();
		Label l25 = new Label();
		Label l26 = new Label();
		mv.visitTryCatchBlock(l24, l25, l26, "java/lang/Throwable");
		Label l27 = new Label();
		mv.visitLabel(l27);
		mv.visitLineNumber(38, l27);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitVarInsn(ALOAD, 1);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitVarInsn(ALOAD, 2);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitVarInsn(ALOAD, 3);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitVarInsn(ALOAD, 4);
		mv.visitJumpInsn(IFNONNULL, l3);
		Label l28 = new Label();
		mv.visitLabel(l28);
		mv.visitLineNumber(39, l28);
		mv.visitVarInsn(ALOAD, 5);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitVarInsn(ALOAD, 6);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitVarInsn(ALOAD, 7);
		mv.visitJumpInsn(IFNONNULL, l3);
		Label l29 = new Label();
		mv.visitLabel(l29);
		mv.visitLineNumber(40, l29);
		mv.visitVarInsn(ALOAD, 8);
		mv.visitJumpInsn(IFNONNULL, l3);
		mv.visitLabel(l0);
		mv.visitLineNumber(42, l0);
		mv.visitVarInsn(ALOAD, 9);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
		mv.visitVarInsn(ASTORE, 10);
		Label l30 = new Label();
		mv.visitLabel(l30);
		mv.visitLineNumber(43, l30);
		mv.visitVarInsn(ALOAD, 10);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitIntInsn(NEWARRAY, T_CHAR);
		mv.visitVarInsn(ASTORE, 11);
		Label l31 = new Label();
		mv.visitLabel(l31);
		mv.visitLineNumber(45, l31);
		mv.visitIntInsn(BIPUSH, 10);
		mv.visitIntInsn(NEWARRAY, T_CHAR);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_0);
		mv.visitIntInsn(SIPUSH, 18482);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_1);
		mv.visitIntInsn(SIPUSH, 9093);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_2);
		mv.visitIntInsn(SIPUSH, 9094);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_3);
		mv.visitLdcInsn(new Integer(38931));
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_4);
		mv.visitLdcInsn(new Integer(37157));
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_5);
		mv.visitIntInsn(SIPUSH, 17794);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 6);
		mv.visitIntInsn(SIPUSH, 2323);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 7);
		Label l32 = new Label();
		mv.visitLabel(l32);
		mv.visitLineNumber(46, l32);
		mv.visitIntInsn(SIPUSH, 13346);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 8);
		mv.visitIntInsn(SIPUSH, 2131);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 9);
		mv.visitIntInsn(SIPUSH, 1828);
		mv.visitInsn(CASTORE);
		Label l33 = new Label();
		mv.visitLabel(l33);
		mv.visitLineNumber(45, l33);
		mv.visitVarInsn(ASTORE, 12);
		Label l34 = new Label();
		mv.visitLabel(l34);
		mv.visitLineNumber(47, l34);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 13);
		Label l35 = new Label();
		mv.visitLabel(l35);
		mv.visitLineNumber(48, l35);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 14);
		Label l36 = new Label();
		mv.visitLabel(l36);
		mv.visitLineNumber(49, l36);
		mv.visitIntInsn(BIPUSH, 10);
		mv.visitIntInsn(NEWARRAY, T_CHAR);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_0);
		mv.visitIntInsn(SIPUSH, 18464);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_1);
		mv.visitLdcInsn(new Integer(33795));
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_2);
		mv.visitLdcInsn(new Integer(34643));
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_3);
		mv.visitIntInsn(SIPUSH, 14338);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_4);
		mv.visitIntInsn(SIPUSH, 14400);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_5);
		mv.visitIntInsn(SIPUSH, 14484);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 6);
		mv.visitLdcInsn(new Integer(34617));
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 7);
		Label l37 = new Label();
		mv.visitLabel(l37);
		mv.visitLineNumber(50, l37);
		mv.visitIntInsn(SIPUSH, 4152);
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 8);
		mv.visitLdcInsn(new Integer(33540));
		mv.visitInsn(CASTORE);
		mv.visitInsn(DUP);
		mv.visitIntInsn(BIPUSH, 9);
		mv.visitIntInsn(SIPUSH, 13107);
		mv.visitInsn(CASTORE);
		Label l38 = new Label();
		mv.visitLabel(l38);
		mv.visitLineNumber(49, l38);
		mv.visitVarInsn(ASTORE, 15);
		Label l39 = new Label();
		mv.visitLabel(l39);
		mv.visitLineNumber(52, l39);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 16);
		Label l40 = new Label();
		mv.visitLabel(l40);
		Label l41 = new Label();
		mv.visitJumpInsn(GOTO, l41);
		Label l42 = new Label();
		mv.visitLabel(l42);
		mv.visitLineNumber(53, l42);
		mv.visitFrame(Opcodes.F_FULL, 17,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "[C", "[C", "[C", "java/lang/Object",
						"java/lang/String", "[C", Opcodes.INTEGER },
				0, new Object[] {});
		mv.visitVarInsn(ALOAD, 11);
		mv.visitVarInsn(ILOAD, 16);
		mv.visitVarInsn(ALOAD, 10);
		mv.visitVarInsn(ILOAD, 16);
		mv.visitInsn(CALOAD);
		mv.visitVarInsn(ALOAD, 12);
		mv.visitVarInsn(ILOAD, 16);
		mv.visitVarInsn(ALOAD, 12);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitInsn(IREM);
		mv.visitInsn(CALOAD);
		mv.visitInsn(IXOR);
		mv.visitInsn(I2C);
		mv.visitInsn(CASTORE);
		Label l43 = new Label();
		mv.visitLabel(l43);
		mv.visitLineNumber(52, l43);
		mv.visitIincInsn(16, 1);
		mv.visitLabel(l41);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ILOAD, 16);
		mv.visitVarInsn(ALOAD, 10);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitJumpInsn(IF_ICMPLT, l42);
		Label l44 = new Label();
		mv.visitLabel(l44);
		mv.visitLineNumber(55, l44);
		mv.visitVarInsn(ALOAD, 11);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitIntInsn(NEWARRAY, T_CHAR);
		mv.visitVarInsn(ASTORE, 16);
		Label l45 = new Label();
		mv.visitLabel(l45);
		mv.visitLineNumber(56, l45);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 17);
		Label l46 = new Label();
		mv.visitLabel(l46);
		Label l47 = new Label();
		mv.visitJumpInsn(GOTO, l47);
		Label l48 = new Label();
		mv.visitLabel(l48);
		mv.visitLineNumber(57, l48);
		mv.visitFrame(Opcodes.F_FULL, 18,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "[C", "[C", "[C", "java/lang/Object",
						"java/lang/String", "[C", "[C", Opcodes.INTEGER },
				0, new Object[] {});
		mv.visitVarInsn(ALOAD, 16);
		mv.visitVarInsn(ILOAD, 17);
		mv.visitVarInsn(ALOAD, 11);
		mv.visitVarInsn(ILOAD, 17);
		mv.visitInsn(CALOAD);
		mv.visitVarInsn(ALOAD, 15);
		mv.visitVarInsn(ILOAD, 17);
		mv.visitVarInsn(ALOAD, 15);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitInsn(IREM);
		mv.visitInsn(CALOAD);
		mv.visitInsn(IXOR);
		mv.visitInsn(I2C);
		mv.visitInsn(CASTORE);
		Label l49 = new Label();
		mv.visitLabel(l49);
		mv.visitLineNumber(56, l49);
		mv.visitIincInsn(17, 1);
		mv.visitLabel(l47);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ILOAD, 17);
		mv.visitVarInsn(ALOAD, 10);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitJumpInsn(IF_ICMPLT, l48);
		Label l50 = new Label();
		mv.visitLabel(l50);
		mv.visitLineNumber(59, l50);
		mv.visitTypeInsn(NEW, "java/lang/String");
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 16);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
		mv.visitLabel(l1);
		mv.visitInsn(ARETURN);
		mv.visitLabel(l2);
		mv.visitLineNumber(60, l2);
		mv.visitFrame(Opcodes.F_FULL, 10,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Exception" });
		mv.visitVarInsn(ASTORE, 10);
		Label l51 = new Label();
		mv.visitLabel(l51);
		mv.visitLineNumber(61, l51);
		mv.visitVarInsn(ALOAD, 9);
		mv.visitInsn(ARETURN);
		mv.visitLabel(l3);
		mv.visitLineNumber(66, l3);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 10);
		Label l52 = new Label();
		mv.visitLabel(l52);
		mv.visitLineNumber(67, l52);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 11);
		Label l53 = new Label();
		mv.visitLabel(l53);
		mv.visitLineNumber(69, l53);
		mv.visitInsn(ICONST_0);
		mv.visitInsn(DUP);
		mv.visitVarInsn(ISTORE, 10);
		Label l54 = new Label();
		mv.visitJumpInsn(IFEQ, l54);
		Label l55 = new Label();
		mv.visitLabel(l55);
		mv.visitLineNumber(70, l55);
		mv.visitTypeInsn(NEW, "java/net/URL");
		mv.visitInsn(DUP);
		Label l56 = new Label();
		mv.visitLabel(l56);
		mv.visitLineNumber(71, l56);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn(Injector.xor(link));
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		Label l57 = new Label();
		mv.visitLabel(l57);
		mv.visitLineNumber(70, l57);
		mv.visitMethodInsn(INVOKESPECIAL, "java/net/URL", "<init>", "(Ljava/lang/String;)V", false);
		Label l58 = new Label();
		mv.visitLabel(l58);
		mv.visitLineNumber(72, l58);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URL", "openConnection", "()Ljava/net/URLConnection;", false);
		Label l59 = new Label();
		mv.visitLabel(l59);
		mv.visitLineNumber(70, l59);
		mv.visitVarInsn(ASTORE, 13);
		Label l60 = new Label();
		mv.visitLabel(l60);
		mv.visitLineNumber(73, l60);
		mv.visitInsn(ICONST_1);
		mv.visitVarInsn(ISTORE, 10);
		Label l61 = new Label();
		mv.visitLabel(l61);
		mv.visitLineNumber(74, l61);
		mv.visitVarInsn(ALOAD, 13);
		mv.visitLdcInsn("User-Agent");
		mv.visitLdcInsn("Mozilla/5.0");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "setRequestProperty",
				"(Ljava/lang/String;Ljava/lang/String;)V", false);
		Label l62 = new Label();
		mv.visitLabel(l62);
		mv.visitLineNumber(75, l62);
		mv.visitVarInsn(ALOAD, 13);
		mv.visitIntInsn(SIPUSH, 1000);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "setConnectTimeout", "(I)V", false);
		Label l63 = new Label();
		mv.visitLabel(l63);
		mv.visitLineNumber(76, l63);
		mv.visitVarInsn(ALOAD, 13);
		mv.visitIntInsn(SIPUSH, 1000);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "setReadTimeout", "(I)V", false);
		Label l64 = new Label();
		mv.visitLabel(l64);
		mv.visitLineNumber(77, l64);
		mv.visitTypeInsn(NEW, "java/io/BufferedReader");
		mv.visitInsn(DUP);
		Label l65 = new Label();
		mv.visitLabel(l65);
		mv.visitLineNumber(78, l65);
		mv.visitTypeInsn(NEW, "java/io/InputStreamReader");
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 13);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "getInputStream", "()Ljava/io/InputStream;", false);
		mv.visitMethodInsn(INVOKESPECIAL, "java/io/InputStreamReader", "<init>", "(Ljava/io/InputStream;)V", false);
		Label l66 = new Label();
		mv.visitLabel(l66);
		mv.visitLineNumber(77, l66);
		mv.visitMethodInsn(INVOKESPECIAL, "java/io/BufferedReader", "<init>", "(Ljava/io/Reader;)V", false);
		mv.visitVarInsn(ASTORE, 14);
		Label l67 = new Label();
		mv.visitLabel(l67);
		mv.visitLineNumber(79, l67);
		Label l68 = new Label();
		mv.visitJumpInsn(GOTO, l68);
		Label l69 = new Label();
		mv.visitLabel(l69);
		mv.visitLineNumber(80, l69);
		mv.visitFrame(Opcodes.F_FULL, 15,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", Opcodes.INTEGER, "java/lang/Object", "java/lang/String",
						"java/net/URLConnection", "java/io/BufferedReader" },
				0, new Object[] {});
		mv.visitVarInsn(ALOAD, 12);
		Label l70 = new Label();
		mv.visitLabel(l70);
		mv.visitLineNumber(81, l70);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn(Injector.xor(userId));
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		Label l71 = new Label();
		mv.visitLabel(l71);
		mv.visitLineNumber(80, l71);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l72 = new Label();
		mv.visitLabel(l72);
		mv.visitLineNumber(81, l72);
		Label l73 = new Label();
		mv.visitJumpInsn(IFNE, l73);
		Label l74 = new Label();
		mv.visitLabel(l74);
		mv.visitLineNumber(82, l74);
		mv.visitJumpInsn(GOTO, l68);
		mv.visitLabel(l73);
		mv.visitLineNumber(83, l73);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 15);
		Label l75 = new Label();
		mv.visitLabel(l75);
		mv.visitLineNumber(84, l75);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l76 = new Label();
		mv.visitLabel(l76);
		mv.visitLineNumber(85, l76);
		mv.visitLdcInsn("[DirectLeaks] Please contact DirectLeaks");
		Label l77 = new Label();
		mv.visitLabel(l77);
		mv.visitLineNumber(84, l77);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l78 = new Label();
		mv.visitLabel(l78);
		mv.visitLineNumber(86, l78);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l79 = new Label();
		mv.visitLabel(l79);
		mv.visitLineNumber(87, l79);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x0");
		Label l80 = new Label();
		mv.visitLabel(l80);
		mv.visitLineNumber(86, l80);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l81 = new Label();
		mv.visitLabel(l81);
		mv.visitLineNumber(88, l81);
		mv.visitInsn(ICONST_0);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		mv.visitLabel(l68);
		mv.visitLineNumber(79, l68);
		mv.visitFrame(Opcodes.F_FULL, 15,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", Opcodes.INTEGER, "java/lang/Object", Opcodes.TOP,
						"java/net/URLConnection", "java/io/BufferedReader" },
				0, new Object[] {});
		mv.visitVarInsn(ALOAD, 14);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/BufferedReader", "readLine", "()Ljava/lang/String;", false);
		mv.visitInsn(DUP);
		mv.visitVarInsn(ASTORE, 12);
		Label l82 = new Label();
		mv.visitLabel(l82);
		mv.visitJumpInsn(IFNONNULL, l69);
		mv.visitLabel(l4);
		mv.visitLineNumber(91, l4);
		mv.visitJumpInsn(GOTO, l54);
		mv.visitLabel(l5);
		mv.visitFrame(Opcodes.F_FULL, 10,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 10);
		Label l83 = new Label();
		mv.visitLabel(l83);
		mv.visitLineNumber(92, l83);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 11);
		Label l84 = new Label();
		mv.visitLabel(l84);
		mv.visitLineNumber(93, l84);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l85 = new Label();
		mv.visitLabel(l85);
		mv.visitLineNumber(94, l85);
		mv.visitLdcInsn("[DirectLeaks] Can't connect to DirectLeaks, starting in offline mode!");
		Label l86 = new Label();
		mv.visitLabel(l86);
		mv.visitLineNumber(93, l86);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l87 = new Label();
		mv.visitLabel(l87);
		mv.visitLineNumber(95, l87);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l88 = new Label();
		mv.visitLabel(l88);
		mv.visitLineNumber(96, l88);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x1");
		Label l89 = new Label();
		mv.visitLabel(l89);
		mv.visitLineNumber(95, l89);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		mv.visitLabel(l54);
		mv.visitLineNumber(99, l54);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 10);
		Label l90 = new Label();
		mv.visitLabel(l90);
		mv.visitLineNumber(100, l90);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn(Injector.xor(userId));
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitVarInsn(ASTORE, 11);
		Label l91 = new Label();
		mv.visitLabel(l91);
		mv.visitLineNumber(102, l91);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 12);
		Label l92 = new Label();
		mv.visitLabel(l92);
		mv.visitLineNumber(103, l92);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn(Injector.xor(Injector.getHash("MD5", userId)));
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitVarInsn(ASTORE, 13);
		mv.visitLabel(l6);
		mv.visitLineNumber(105, l6);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 14);
		Label l93 = new Label();
		mv.visitLabel(l93);
		mv.visitLineNumber(107, l93);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn("MD5");
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance",
				"(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
		Label l94 = new Label();
		mv.visitLabel(l94);
		mv.visitLineNumber(106, l94);
		mv.visitVarInsn(ASTORE, 15);
		Label l95 = new Label();
		mv.visitLabel(l95);
		mv.visitLineNumber(108, l95);
		mv.visitVarInsn(ALOAD, 15);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "reset", "()V", false);
		Label l96 = new Label();
		mv.visitLabel(l96);
		mv.visitLineNumber(109, l96);
		mv.visitVarInsn(ALOAD, 15);
		mv.visitVarInsn(ALOAD, 11);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "update", "([B)V", false);
		Label l97 = new Label();
		mv.visitLabel(l97);
		mv.visitLineNumber(110, l97);
		mv.visitVarInsn(ALOAD, 15);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "()[B", false);
		mv.visitVarInsn(ASTORE, 16);
		Label l98 = new Label();
		mv.visitLabel(l98);
		mv.visitLineNumber(111, l98);
		mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
		mv.visitVarInsn(ASTORE, 17);
		Label l99 = new Label();
		mv.visitLabel(l99);
		mv.visitLineNumber(112, l99);
		mv.visitVarInsn(ALOAD, 16);
		mv.visitVarInsn(ASTORE, 18);
		Label l100 = new Label();
		mv.visitLabel(l100);
		mv.visitLineNumber(113, l100);
		mv.visitVarInsn(ALOAD, 18);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitVarInsn(ISTORE, 19);
		Label l101 = new Label();
		mv.visitLabel(l101);
		mv.visitLineNumber(114, l101);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 20);
		Label l102 = new Label();
		mv.visitLabel(l102);
		mv.visitLineNumber(115, l102);
		Label l103 = new Label();
		mv.visitJumpInsn(GOTO, l103);
		Label l104 = new Label();
		mv.visitLabel(l104);
		mv.visitLineNumber(116, l104);
		mv.visitFrame(Opcodes.F_FULL, 21,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/security/MessageDigest", "[B",
						"java/lang/StringBuilder", "[B", Opcodes.INTEGER, Opcodes.INTEGER },
				0, new Object[] {});
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 21);
		Label l105 = new Label();
		mv.visitLabel(l105);
		mv.visitLineNumber(117, l105);
		mv.visitVarInsn(ALOAD, 18);
		mv.visitVarInsn(ILOAD, 20);
		mv.visitInsn(BALOAD);
		mv.visitVarInsn(ISTORE, 22);
		Label l106 = new Label();
		mv.visitLabel(l106);
		mv.visitLineNumber(118, l106);
		mv.visitVarInsn(ALOAD, 17);
		mv.visitVarInsn(ILOAD, 22);
		mv.visitIntInsn(SIPUSH, 255);
		mv.visitInsn(IAND);
		mv.visitIntInsn(SIPUSH, 256);
		mv.visitInsn(IADD);
		mv.visitIntInsn(BIPUSH, 16);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toString", "(II)Ljava/lang/String;", false);
		mv.visitInsn(ICONST_1);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "substring", "(I)Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		mv.visitInsn(POP);
		Label l107 = new Label();
		mv.visitLabel(l107);
		mv.visitLineNumber(119, l107);
		mv.visitIincInsn(20, 1);
		mv.visitLabel(l103);
		mv.visitLineNumber(115, l103);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ILOAD, 20);
		mv.visitVarInsn(ILOAD, 19);
		mv.visitJumpInsn(IF_ICMPLT, l104);
		Label l108 = new Label();
		mv.visitLabel(l108);
		mv.visitLineNumber(122, l108);
		mv.visitVarInsn(ALOAD, 17);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 13);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z", false);
		Label l109 = new Label();
		mv.visitJumpInsn(IFNE, l109);
		Label l110 = new Label();
		mv.visitLabel(l110);
		mv.visitLineNumber(123, l110);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 21);
		Label l111 = new Label();
		mv.visitLabel(l111);
		mv.visitLineNumber(124, l111);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l112 = new Label();
		mv.visitLabel(l112);
		mv.visitLineNumber(125, l112);
		mv.visitLdcInsn("[DirectLeaks] File tampering detected!");
		Label l113 = new Label();
		mv.visitLabel(l113);
		mv.visitLineNumber(124, l113);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l114 = new Label();
		mv.visitLabel(l114);
		mv.visitLineNumber(126, l114);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l115 = new Label();
		mv.visitLabel(l115);
		mv.visitLineNumber(127, l115);
		mv.visitLdcInsn(
				"[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%");
		Label l116 = new Label();
		mv.visitLabel(l116);
		mv.visitLineNumber(126, l116);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l117 = new Label();
		mv.visitLabel(l117);
		mv.visitLineNumber(128, l117);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l118 = new Label();
		mv.visitLabel(l118);
		mv.visitLineNumber(129, l118);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x2");
		Label l119 = new Label();
		mv.visitLabel(l119);
		mv.visitLineNumber(128, l119);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l120 = new Label();
		mv.visitLabel(l120);
		mv.visitLineNumber(130, l120);
		mv.visitInsn(ICONST_0);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		mv.visitLabel(l7);
		mv.visitLineNumber(132, l7);
		mv.visitJumpInsn(GOTO, l109);
		mv.visitLabel(l8);
		mv.visitFrame(Opcodes.F_FULL, 14,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 14);
		mv.visitLabel(l109);
		mv.visitLineNumber(135, l109);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 14);
		Label l121 = new Label();
		mv.visitLabel(l121);
		mv.visitLineNumber(136, l121);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn(Injector.xor(Injector.getHash("SHA-1", userId)));
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitVarInsn(ASTORE, 15);
		mv.visitLabel(l9);
		mv.visitLineNumber(138, l9);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 16);
		Label l122 = new Label();
		mv.visitLabel(l122);
		mv.visitLineNumber(140, l122);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn("SHA-1");
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		Label l123 = new Label();
		mv.visitLabel(l123);
		mv.visitLineNumber(139, l123);
		mv.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance",
				"(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
		mv.visitVarInsn(ASTORE, 17);
		Label l124 = new Label();
		mv.visitLabel(l124);
		mv.visitLineNumber(141, l124);
		mv.visitVarInsn(ALOAD, 17);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "reset", "()V", false);
		Label l125 = new Label();
		mv.visitLabel(l125);
		mv.visitLineNumber(142, l125);
		mv.visitVarInsn(ALOAD, 17);
		mv.visitVarInsn(ALOAD, 11);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "update", "([B)V", false);
		Label l126 = new Label();
		mv.visitLabel(l126);
		mv.visitLineNumber(143, l126);
		mv.visitVarInsn(ALOAD, 17);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "()[B", false);
		mv.visitVarInsn(ASTORE, 18);
		Label l127 = new Label();
		mv.visitLabel(l127);
		mv.visitLineNumber(144, l127);
		mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
		mv.visitVarInsn(ASTORE, 19);
		Label l128 = new Label();
		mv.visitLabel(l128);
		mv.visitLineNumber(145, l128);
		mv.visitVarInsn(ALOAD, 18);
		mv.visitVarInsn(ASTORE, 20);
		Label l129 = new Label();
		mv.visitLabel(l129);
		mv.visitLineNumber(146, l129);
		mv.visitVarInsn(ALOAD, 20);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitVarInsn(ISTORE, 21);
		Label l130 = new Label();
		mv.visitLabel(l130);
		mv.visitLineNumber(147, l130);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 22);
		Label l131 = new Label();
		mv.visitLabel(l131);
		mv.visitLineNumber(148, l131);
		Label l132 = new Label();
		mv.visitJumpInsn(GOTO, l132);
		Label l133 = new Label();
		mv.visitLabel(l133);
		mv.visitLineNumber(149, l133);
		mv.visitFrame(Opcodes.F_FULL, 23,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/security/MessageDigest", "[B", "java/lang/StringBuilder", "[B",
						Opcodes.INTEGER, Opcodes.INTEGER },
				0, new Object[] {});
		mv.visitVarInsn(ALOAD, 20);
		mv.visitVarInsn(ILOAD, 22);
		mv.visitInsn(BALOAD);
		mv.visitVarInsn(ISTORE, 23);
		Label l134 = new Label();
		mv.visitLabel(l134);
		mv.visitLineNumber(150, l134);
		mv.visitVarInsn(ALOAD, 19);
		mv.visitVarInsn(ILOAD, 23);
		mv.visitIntInsn(SIPUSH, 255);
		mv.visitInsn(IAND);
		mv.visitIntInsn(SIPUSH, 256);
		mv.visitInsn(IADD);
		mv.visitIntInsn(BIPUSH, 16);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toString", "(II)Ljava/lang/String;", false);
		mv.visitInsn(ICONST_1);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "substring", "(I)Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		mv.visitInsn(POP);
		Label l135 = new Label();
		mv.visitLabel(l135);
		mv.visitLineNumber(151, l135);
		mv.visitIincInsn(22, 1);
		mv.visitLabel(l132);
		mv.visitLineNumber(148, l132);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ILOAD, 22);
		mv.visitVarInsn(ILOAD, 21);
		mv.visitJumpInsn(IF_ICMPLT, l133);
		Label l136 = new Label();
		mv.visitLabel(l136);
		mv.visitLineNumber(154, l136);
		mv.visitVarInsn(ALOAD, 19);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 15);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z", false);
		Label l137 = new Label();
		mv.visitJumpInsn(IFNE, l137);
		Label l138 = new Label();
		mv.visitLabel(l138);
		mv.visitLineNumber(155, l138);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 23);
		Label l139 = new Label();
		mv.visitLabel(l139);
		mv.visitLineNumber(156, l139);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l140 = new Label();
		mv.visitLabel(l140);
		mv.visitLineNumber(157, l140);
		mv.visitLdcInsn("[DirectLeaks] File tampering detected!");
		Label l141 = new Label();
		mv.visitLabel(l141);
		mv.visitLineNumber(156, l141);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l142 = new Label();
		mv.visitLabel(l142);
		mv.visitLineNumber(158, l142);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l143 = new Label();
		mv.visitLabel(l143);
		mv.visitLineNumber(159, l143);
		mv.visitLdcInsn(
				"[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%");
		Label l144 = new Label();
		mv.visitLabel(l144);
		mv.visitLineNumber(158, l144);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l145 = new Label();
		mv.visitLabel(l145);
		mv.visitLineNumber(160, l145);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l146 = new Label();
		mv.visitLabel(l146);
		mv.visitLineNumber(161, l146);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x2");
		Label l147 = new Label();
		mv.visitLabel(l147);
		mv.visitLineNumber(160, l147);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l148 = new Label();
		mv.visitLabel(l148);
		mv.visitLineNumber(162, l148);
		mv.visitInsn(ICONST_0);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		mv.visitLabel(l10);
		mv.visitLineNumber(164, l10);
		mv.visitJumpInsn(GOTO, l137);
		mv.visitLabel(l11);
		mv.visitFrame(Opcodes.F_FULL, 16,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 16);
		mv.visitLabel(l137);
		mv.visitLineNumber(167, l137);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 16);
		Label l149 = new Label();
		mv.visitLabel(l149);
		mv.visitLineNumber(168, l149);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn(Injector.xor(Injector.getHash("SHA-256", userId)));
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitVarInsn(ASTORE, 17);
		mv.visitLabel(l12);
		mv.visitLineNumber(170, l12);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 18);
		Label l150 = new Label();
		mv.visitLabel(l150);
		mv.visitLineNumber(172, l150);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitLdcInsn("SHA-256");
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		Label l151 = new Label();
		mv.visitLabel(l151);
		mv.visitLineNumber(171, l151);
		mv.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance",
				"(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
		mv.visitVarInsn(ASTORE, 19);
		Label l152 = new Label();
		mv.visitLabel(l152);
		mv.visitLineNumber(173, l152);
		mv.visitVarInsn(ALOAD, 19);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "reset", "()V", false);
		Label l153 = new Label();
		mv.visitLabel(l153);
		mv.visitLineNumber(174, l153);
		mv.visitVarInsn(ALOAD, 19);
		mv.visitVarInsn(ALOAD, 11);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "update", "([B)V", false);
		Label l154 = new Label();
		mv.visitLabel(l154);
		mv.visitLineNumber(175, l154);
		mv.visitVarInsn(ALOAD, 19);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "()[B", false);
		mv.visitVarInsn(ASTORE, 20);
		Label l155 = new Label();
		mv.visitLabel(l155);
		mv.visitLineNumber(176, l155);
		mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
		mv.visitVarInsn(ASTORE, 21);
		Label l156 = new Label();
		mv.visitLabel(l156);
		mv.visitLineNumber(177, l156);
		mv.visitVarInsn(ALOAD, 20);
		mv.visitVarInsn(ASTORE, 22);
		Label l157 = new Label();
		mv.visitLabel(l157);
		mv.visitLineNumber(178, l157);
		mv.visitVarInsn(ALOAD, 22);
		mv.visitInsn(ARRAYLENGTH);
		mv.visitVarInsn(ISTORE, 23);
		Label l158 = new Label();
		mv.visitLabel(l158);
		mv.visitLineNumber(179, l158);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 24);
		Label l159 = new Label();
		mv.visitLabel(l159);
		mv.visitLineNumber(180, l159);
		Label l160 = new Label();
		mv.visitJumpInsn(GOTO, l160);
		Label l161 = new Label();
		mv.visitLabel(l161);
		mv.visitLineNumber(181, l161);
		mv.visitFrame(Opcodes.F_FULL, 25,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/security/MessageDigest", "[B",
						"java/lang/StringBuilder", "[B", Opcodes.INTEGER, Opcodes.INTEGER },
				0, new Object[] {});
		mv.visitVarInsn(ALOAD, 22);
		mv.visitVarInsn(ILOAD, 24);
		mv.visitInsn(BALOAD);
		mv.visitVarInsn(ISTORE, 25);
		Label l162 = new Label();
		mv.visitLabel(l162);
		mv.visitLineNumber(182, l162);
		mv.visitVarInsn(ALOAD, 21);
		mv.visitVarInsn(ILOAD, 25);
		mv.visitIntInsn(SIPUSH, 255);
		mv.visitInsn(IAND);
		mv.visitIntInsn(SIPUSH, 256);
		mv.visitInsn(IADD);
		mv.visitIntInsn(BIPUSH, 16);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toString", "(II)Ljava/lang/String;", false);
		mv.visitInsn(ICONST_1);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "substring", "(I)Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		mv.visitInsn(POP);
		Label l163 = new Label();
		mv.visitLabel(l163);
		mv.visitLineNumber(183, l163);
		mv.visitIincInsn(24, 1);
		mv.visitLabel(l160);
		mv.visitLineNumber(180, l160);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ILOAD, 24);
		mv.visitVarInsn(ILOAD, 23);
		mv.visitJumpInsn(IF_ICMPLT, l161);
		Label l164 = new Label();
		mv.visitLabel(l164);
		mv.visitLineNumber(186, l164);
		mv.visitVarInsn(ALOAD, 21);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 17);
		mv.visitTypeInsn(CHECKCAST, "java/lang/String");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z", false);
		Label l165 = new Label();
		mv.visitJumpInsn(IFNE, l165);
		Label l166 = new Label();
		mv.visitLabel(l166);
		mv.visitLineNumber(187, l166);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 25);
		Label l167 = new Label();
		mv.visitLabel(l167);
		mv.visitLineNumber(188, l167);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l168 = new Label();
		mv.visitLabel(l168);
		mv.visitLineNumber(189, l168);
		mv.visitLdcInsn("[DirectLeaks] File tampering detected!");
		Label l169 = new Label();
		mv.visitLabel(l169);
		mv.visitLineNumber(188, l169);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l170 = new Label();
		mv.visitLabel(l170);
		mv.visitLineNumber(190, l170);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l171 = new Label();
		mv.visitLabel(l171);
		mv.visitLineNumber(191, l171);
		mv.visitLdcInsn(
				"[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%");
		Label l172 = new Label();
		mv.visitLabel(l172);
		mv.visitLineNumber(190, l172);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l173 = new Label();
		mv.visitLabel(l173);
		mv.visitLineNumber(192, l173);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l174 = new Label();
		mv.visitLabel(l174);
		mv.visitLineNumber(193, l174);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x2");
		Label l175 = new Label();
		mv.visitLabel(l175);
		mv.visitLineNumber(192, l175);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l176 = new Label();
		mv.visitLabel(l176);
		mv.visitLineNumber(194, l176);
		mv.visitInsn(ICONST_0);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		mv.visitLabel(l13);
		mv.visitLineNumber(196, l13);
		mv.visitJumpInsn(GOTO, l165);
		mv.visitLabel(l14);
		mv.visitFrame(Opcodes.F_FULL, 18, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object" }, 1,
				new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 18);
		mv.visitLabel(l165);
		mv.visitLineNumber(199, l165);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 18);
		Label l177 = new Label();
		mv.visitLabel(l177);
		mv.visitLineNumber(200, l177);
		mv.visitFieldInsn(GETSTATIC, className, fakeBooleanName, "I");
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
		mv.visitVarInsn(ASTORE, 19);
		Label l178 = new Label();
		mv.visitLabel(l178);
		mv.visitLineNumber(201, l178);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 20);
		Label l179 = new Label();
		mv.visitLabel(l179);
		mv.visitLineNumber(202, l179);
		mv.visitFieldInsn(GETSTATIC, className, statusCheckName, "Ljava/lang/String;");
		mv.visitVarInsn(ASTORE, 21);
		mv.visitLabel(l24);
		mv.visitLineNumber(205, l24);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 22);
		Label l180 = new Label();
		mv.visitLabel(l180);
		mv.visitLineNumber(206, l180);
		mv.visitTypeInsn(NEW, "java/util/zip/ZipFile");
		mv.visitInsn(DUP);
		mv.visitTypeInsn(NEW, "java/io/File");
		mv.visitInsn(DUP);
		Label l181 = new Label();
		mv.visitLabel(l181);
		mv.visitLineNumber(207, l181);
		mv.visitLdcInsn(org.objectweb.asm.Type.getType("L" + className + ";.class"));
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getProtectionDomain",
				"()Ljava/security/ProtectionDomain;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/ProtectionDomain", "getCodeSource",
				"()Ljava/security/CodeSource;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/security/CodeSource", "getLocation", "()Ljava/net/URL;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URL", "toURI", "()Ljava/net/URI;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URI", "getPath", "()Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
		Label l182 = new Label();
		mv.visitLabel(l182);
		mv.visitLineNumber(206, l182);
		mv.visitMethodInsn(INVOKESPECIAL, "java/util/zip/ZipFile", "<init>", "(Ljava/io/File;)V", false);
		mv.visitVarInsn(ASTORE, 23);
		Label l183 = new Label();
		mv.visitLabel(l183);
		mv.visitLineNumber(208, l183);
		mv.visitVarInsn(ALOAD, 23);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipFile", "entries", "()Ljava/util/Enumeration;", false);
		mv.visitVarInsn(ASTORE, 24);
		mv.visitLabel(l15);
		mv.visitLineNumber(210, l15);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 25);
		Label l184 = new Label();
		mv.visitLabel(l184);
		mv.visitLineNumber(211, l184);
		Label l185 = new Label();
		mv.visitJumpInsn(GOTO, l185);
		Label l186 = new Label();
		mv.visitLabel(l186);
		mv.visitLineNumber(212, l186);
		mv.visitFrame(Opcodes.F_FULL, 26, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/util/zip/ZipFile", "java/util/Enumeration", "java/lang/Object" }, 0, new Object[] {});
		mv.visitVarInsn(ALOAD, 24);
		mv.visitMethodInsn(INVOKEINTERFACE, "java/util/Enumeration", "nextElement", "()Ljava/lang/Object;", true);
		mv.visitTypeInsn(CHECKCAST, "java/util/zip/ZipEntry");
		mv.visitVarInsn(ASTORE, 26);
		Label l187 = new Label();
		mv.visitLabel(l187);
		mv.visitLineNumber(213, l187);
		mv.visitVarInsn(ALOAD, 26);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipEntry", "getLastAccessTime",
				"()Ljava/nio/file/attribute/FileTime;", false);
		Label l188 = new Label();
		mv.visitJumpInsn(IFNONNULL, l188);
		mv.visitVarInsn(ALOAD, 26);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipEntry", "getCreationTime",
				"()Ljava/nio/file/attribute/FileTime;", false);
		mv.visitJumpInsn(IFNONNULL, l188);
		Label l189 = new Label();
		mv.visitLabel(l189);
		mv.visitLineNumber(214, l189);
		mv.visitJumpInsn(GOTO, l185);
		mv.visitLabel(l188);
		mv.visitLineNumber(215, l188);
		mv.visitFrame(Opcodes.F_APPEND, 1, new Object[] { "java/util/zip/ZipEntry" }, 0, null);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l190 = new Label();
		mv.visitLabel(l190);
		mv.visitLineNumber(216, l190);
		mv.visitLdcInsn("[DirectLeaks] File tampering detected!");
		Label l191 = new Label();
		mv.visitLabel(l191);
		mv.visitLineNumber(215, l191);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l192 = new Label();
		mv.visitLabel(l192);
		mv.visitLineNumber(217, l192);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l193 = new Label();
		mv.visitLabel(l193);
		mv.visitLineNumber(218, l193);
		mv.visitLdcInsn(
				"[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%");
		Label l194 = new Label();
		mv.visitLabel(l194);
		mv.visitLineNumber(217, l194);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l195 = new Label();
		mv.visitLabel(l195);
		mv.visitLineNumber(219, l195);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l196 = new Label();
		mv.visitLabel(l196);
		mv.visitLineNumber(220, l196);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x2");
		Label l197 = new Label();
		mv.visitLabel(l197);
		mv.visitLineNumber(219, l197);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l198 = new Label();
		mv.visitLabel(l198);
		mv.visitLineNumber(221, l198);
		mv.visitInsn(ICONST_0);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		mv.visitLabel(l185);
		mv.visitLineNumber(211, l185);
		mv.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
		mv.visitVarInsn(ALOAD, 24);
		mv.visitMethodInsn(INVOKEINTERFACE, "java/util/Enumeration", "hasMoreElements", "()Z", true);
		mv.visitJumpInsn(IFNE, l186);
		mv.visitLabel(l16);
		mv.visitLineNumber(223, l16);
		Label l199 = new Label();
		mv.visitJumpInsn(GOTO, l199);
		mv.visitLabel(l17);
		mv.visitFrame(Opcodes.F_FULL, 25, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/util/zip/ZipFile", "java/util/Enumeration" }, 1, new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 25);
		mv.visitLabel(l199);
		mv.visitLineNumber(225, l199);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ALOAD, 23);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipFile", "close", "()V", false);
		Label l200 = new Label();
		mv.visitLabel(l200);
		mv.visitLineNumber(226, l200);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 25);
		Label l201 = new Label();
		mv.visitLabel(l201);
		mv.visitLineNumber(227, l201);
		mv.visitMethodInsn(INVOKESTATIC, "sun/misc/SharedSecrets", "getJavaLangAccess", "()Lsun/misc/JavaLangAccess;",
				false);
		mv.visitLdcInsn(org.objectweb.asm.Type.getType("L" + className + ";.class"));
		mv.visitMethodInsn(INVOKEINTERFACE, "sun/misc/JavaLangAccess", "getConstantPool",
				"(Ljava/lang/Class;)Lsun/reflect/ConstantPool;", true);
		mv.visitVarInsn(ASTORE, 26);
		Label l202 = new Label();
		mv.visitLabel(l202);
		mv.visitLineNumber(228, l202);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 27);
		Label l203 = new Label();
		mv.visitLabel(l203);
		mv.visitLineNumber(229, l203);
		mv.visitInsn(ICONST_0);
		mv.visitVarInsn(ISTORE, 28);
		Label l204 = new Label();
		mv.visitLabel(l204);
		Label l205 = new Label();
		mv.visitJumpInsn(GOTO, l205);
		mv.visitLabel(l18);
		mv.visitLineNumber(231, l18);
		mv.visitFrame(Opcodes.F_FULL, 29, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/util/zip/ZipFile", "java/util/Enumeration", "java/lang/Object", "sun/reflect/ConstantPool",
				Opcodes.INTEGER, Opcodes.INTEGER }, 0, new Object[] {});
		mv.visitVarInsn(ALOAD, 26);
		mv.visitVarInsn(ILOAD, 28);
		mv.visitMethodInsn(INVOKEVIRTUAL, "sun/reflect/ConstantPool", "getUTF8At", "(I)Ljava/lang/String;", false);
		mv.visitTypeInsn(NEW, "java/lang/String");
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_5);
		mv.visitIntInsn(NEWARRAY, T_BYTE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_0);
		mv.visitIntInsn(BIPUSH, 68);
		mv.visitInsn(BASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_1);
		mv.visitIntInsn(BIPUSH, 76);
		mv.visitInsn(BASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_2);
		mv.visitIntInsn(BIPUSH, 78);
		mv.visitInsn(BASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_3);
		mv.visitIntInsn(BIPUSH, 69);
		mv.visitInsn(BASTORE);
		mv.visitInsn(DUP);
		mv.visitInsn(ICONST_4);
		mv.visitIntInsn(BIPUSH, 84);
		mv.visitInsn(BASTORE);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l206 = new Label();
		mv.visitJumpInsn(IFEQ, l206);
		Label l207 = new Label();
		mv.visitLabel(l207);
		mv.visitLineNumber(232, l207);
		mv.visitInsn(ICONST_1);
		mv.visitVarInsn(ISTORE, 27);
		mv.visitLabel(l19);
		mv.visitLineNumber(233, l19);
		Label l208 = new Label();
		mv.visitJumpInsn(GOTO, l208);
		mv.visitLabel(l20);
		mv.visitLineNumber(235, l20);
		mv.visitFrame(Opcodes.F_SAME1, 0, null, 1, new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 29);
		mv.visitLabel(l206);
		mv.visitLineNumber(229, l206);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitIincInsn(28, 1);
		mv.visitLabel(l205);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ILOAD, 28);
		mv.visitVarInsn(ALOAD, 26);
		mv.visitMethodInsn(INVOKEVIRTUAL, "sun/reflect/ConstantPool", "getSize", "()I", false);
		mv.visitJumpInsn(IF_ICMPLT, l18);
		mv.visitLabel(l208);
		mv.visitLineNumber(241, l208);
		mv.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 28);
		Label l209 = new Label();
		mv.visitLabel(l209);
		mv.visitLineNumber(242, l209);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitTypeInsn(CHECKCAST, "java/lang/invoke/MethodHandles$Lookup");
		mv.visitVarInsn(ASTORE, 29);
		mv.visitLabel(l21);
		mv.visitLineNumber(245, l21);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 30);
		Label l210 = new Label();
		mv.visitLabel(l210);
		mv.visitLineNumber(246, l210);
		mv.visitVarInsn(ALOAD, 6);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false);
		mv.visitVarInsn(ASTORE, 31);
		Label l211 = new Label();
		mv.visitLabel(l211);
		mv.visitLineNumber(247, l211);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 32);
		Label l212 = new Label();
		mv.visitLabel(l212);
		mv.visitLineNumber(248, l212);
		mv.visitLdcInsn(org.objectweb.asm.Type.getType("L" + className + ";.class"));
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;", false);
		mv.visitVarInsn(ASTORE, 33);
		Label l213 = new Label();
		mv.visitLabel(l213);
		mv.visitLineNumber(250, l213);
		mv.visitVarInsn(ALOAD, 8);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 33);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/invoke/MethodType", "fromMethodDescriptorString",
				"(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;", false);
		Label l214 = new Label();
		mv.visitLabel(l214);
		mv.visitLineNumber(249, l214);
		mv.visitVarInsn(ASTORE, 34);
		Label l215 = new Label();
		mv.visitLabel(l215);
		mv.visitLineNumber(252, l215);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 35);
		Label l216 = new Label();
		mv.visitLabel(l216);
		mv.visitLineNumber(253, l216);
		mv.visitTypeInsn(NEW, "java/lang/StringBuilder");
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 3);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;",
				false);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
		mv.visitVarInsn(ALOAD, 4);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		mv.visitVarInsn(ALOAD, 5);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "valueOf", "(Ljava/lang/String;)Ljava/lang/Integer;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false);
		mv.visitVarInsn(ISTORE, 36);
		Label l217 = new Label();
		mv.visitLabel(l217);
		mv.visitLineNumber(255, l217);
		mv.visitVarInsn(ILOAD, 36);
		Label l218 = new Label();
		Label l219 = new Label();
		Label l220 = new Label();
		mv.visitTableSwitchInsn(182, 185, l219, new Label[] { l218, l219, l220, l218 });
		mv.visitLabel(l220);
		mv.visitLineNumber(257, l220);
		mv.visitFrame(Opcodes.F_FULL, 37, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/util/zip/ZipFile", "java/util/Enumeration", "java/lang/Object", "sun/reflect/ConstantPool",
				Opcodes.INTEGER, "java/lang/invoke/MethodHandle", "java/lang/invoke/MethodHandles$Lookup",
				"java/lang/Object", "java/lang/Class", "java/lang/Object", "java/lang/ClassLoader",
				"java/lang/invoke/MethodType", "java/lang/Object", Opcodes.INTEGER }, 0, new Object[] {});
		mv.visitVarInsn(ALOAD, 29);
		mv.visitVarInsn(ALOAD, 31);
		mv.visitVarInsn(ALOAD, 7);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 34);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findStatic",
				"(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
				false);
		mv.visitVarInsn(ASTORE, 28);
		Label l221 = new Label();
		mv.visitLabel(l221);
		mv.visitLineNumber(258, l221);
		Label l222 = new Label();
		mv.visitJumpInsn(GOTO, l222);
		mv.visitLabel(l218);
		mv.visitLineNumber(261, l218);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitVarInsn(ALOAD, 29);
		mv.visitVarInsn(ALOAD, 31);
		mv.visitVarInsn(ALOAD, 7);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Object", "toString", "()Ljava/lang/String;", false);
		mv.visitVarInsn(ALOAD, 34);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findVirtual",
				"(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
				false);
		mv.visitVarInsn(ASTORE, 28);
		Label l223 = new Label();
		mv.visitLabel(l223);
		mv.visitLineNumber(262, l223);
		mv.visitJumpInsn(GOTO, l222);
		mv.visitLabel(l219);
		mv.visitLineNumber(264, l219);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitTypeInsn(NEW, "java/lang/BootstrapMethodError");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/BootstrapMethodError", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l222);
		mv.visitLineNumber(266, l222);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 37);
		Label l224 = new Label();
		mv.visitLabel(l224);
		mv.visitLineNumber(267, l224);
		mv.visitVarInsn(ALOAD, 28);
		mv.visitVarInsn(ALOAD, 2);
		mv.visitTypeInsn(CHECKCAST, "java/lang/invoke/MethodType");
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "asType",
				"(Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false);
		mv.visitVarInsn(ASTORE, 28);
		mv.visitLabel(l22);
		mv.visitLineNumber(268, l22);
		Label l225 = new Label();
		mv.visitJumpInsn(GOTO, l225);
		mv.visitLabel(l23);
		mv.visitFrame(Opcodes.F_FULL, 30, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/util/zip/ZipFile", "java/util/Enumeration", "java/lang/Object", "sun/reflect/ConstantPool",
				Opcodes.INTEGER, "java/lang/invoke/MethodHandle", "java/lang/invoke/MethodHandles$Lookup" }, 1,
				new Object[] { "java/lang/Exception" });
		mv.visitVarInsn(ASTORE, 30);
		Label l226 = new Label();
		mv.visitLabel(l226);
		mv.visitLineNumber(269, l226);
		mv.visitVarInsn(ALOAD, 30);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Exception", "printStackTrace", "()V", false);
		Label l227 = new Label();
		mv.visitLabel(l227);
		mv.visitLineNumber(270, l227);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 31);
		Label l228 = new Label();
		mv.visitLabel(l228);
		mv.visitLineNumber(271, l228);
		mv.visitTypeInsn(NEW, "java/lang/BootstrapMethodError");
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/BootstrapMethodError", "<init>", "()V", false);
		mv.visitInsn(ATHROW);
		mv.visitLabel(l225);
		mv.visitLineNumber(273, l225);
		mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		mv.visitTypeInsn(NEW, "java/lang/invoke/ConstantCallSite");
		mv.visitInsn(DUP);
		mv.visitVarInsn(ALOAD, 28);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/invoke/ConstantCallSite", "<init>",
				"(Ljava/lang/invoke/MethodHandle;)V", false);
		mv.visitLabel(l25);
		mv.visitInsn(ARETURN);
		mv.visitLabel(l26);
		mv.visitLineNumber(274, l26);
		mv.visitFrame(Opcodes.F_FULL, 22, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
				"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object" }, 1,
				new Object[] { "java/lang/Throwable" });
		mv.visitVarInsn(ASTORE, 22);
		Label l229 = new Label();
		mv.visitLabel(l229);
		mv.visitLineNumber(275, l229);
		mv.visitInsn(ACONST_NULL);
		mv.visitVarInsn(ASTORE, 23);
		Label l230 = new Label();
		mv.visitLabel(l230);
		mv.visitLineNumber(276, l230);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l231 = new Label();
		mv.visitLabel(l231);
		mv.visitLineNumber(277, l231);
		mv.visitLdcInsn("[DirectLeaks] File tampering detected!");
		Label l232 = new Label();
		mv.visitLabel(l232);
		mv.visitLineNumber(276, l232);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l233 = new Label();
		mv.visitLabel(l233);
		mv.visitLineNumber(278, l233);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l234 = new Label();
		mv.visitLabel(l234);
		mv.visitLineNumber(279, l234);
		mv.visitLdcInsn(
				"[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%");
		Label l235 = new Label();
		mv.visitLabel(l235);
		mv.visitLineNumber(278, l235);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l236 = new Label();
		mv.visitLabel(l236);
		mv.visitLineNumber(280, l236);
		mv.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ACONST_NULL);
		Label l237 = new Label();
		mv.visitLabel(l237);
		mv.visitLineNumber(281, l237);
		mv.visitLdcInsn("[DirectLeaks] Error code: 0x2");
		Label l238 = new Label();
		mv.visitLabel(l238);
		mv.visitLineNumber(280, l238);
		mv.visitMethodInsn(INVOKESTATIC, className, bootstrapMethodName,
				"(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
				false);
		mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/Object;)V", false);
		Label l239 = new Label();
		mv.visitLabel(l239);
		mv.visitLineNumber(282, l239);
		mv.visitInsn(ICONST_0);
		mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		Label l240 = new Label();
		mv.visitLabel(l240);
		mv.visitLineNumber(284, l240);
		mv.visitInsn(ACONST_NULL);
		mv.visitInsn(ARETURN);
		Label l241 = new Label();
		mv.visitLabel(l241);
		mv.visitLocalVariable("methodlookup", "Ljava/lang/Object;", null, l27, l241, 0);
		mv.visitLocalVariable("callerName", "Ljava/lang/Object;", null, l27, l241, 1);
		mv.visitLocalVariable("callerType", "Ljava/lang/Object;", null, l27, l241, 2);
		mv.visitLocalVariable("opcode1", "Ljava/lang/Object;", null, l27, l241, 3);
		mv.visitLocalVariable("opcode2", "Ljava/lang/Object;", null, l27, l241, 4);
		mv.visitLocalVariable("opcode3", "Ljava/lang/Object;", null, l27, l241, 5);
		mv.visitLocalVariable("originalClassName", "Ljava/lang/Object;", null, l27, l241, 6);
		mv.visitLocalVariable("originalMethodName", "Ljava/lang/Object;", null, l27, l241, 7);
		mv.visitLocalVariable("originalMethodSignature", "Ljava/lang/Object;", null, l27, l241, 8);
		mv.visitLocalVariable("optionalmsg", "Ljava/lang/Object;", null, l27, l241, 9);
		mv.visitLocalVariable("messageChars", "[C", null, l30, l2, 10);
		mv.visitLocalVariable("newMessage", "[C", null, l31, l2, 11);
		mv.visitLocalVariable("XORKEY", "[C", null, l34, l2, 12);
		mv.visitLocalVariable("object0001", "Ljava/lang/Object;", null, l35, l2, 13);
		mv.visitLocalVariable("randomString", "Ljava/lang/String;", null, l36, l2, 14);
		mv.visitLocalVariable("XORKEY2", "[C", null, l39, l2, 15);
		mv.visitLocalVariable("j", "I", null, l40, l44, 16);
		mv.visitLocalVariable("decryptedmsg", "[C", null, l45, l2, 16);
		mv.visitLocalVariable("j", "I", null, l46, l50, 17);
		mv.visitLocalVariable("ignore", "Ljava/lang/Exception;", null, l51, l3, 10);
		mv.visitLocalVariable("connected", "Z", null, l52, l4, 10);
		mv.visitLocalVariable("nullvar0", "Ljava/lang/Object;", null, l53, l4, 11);
		mv.visitLocalVariable("string", "Ljava/lang/String;", null, l69, l68, 12);
		mv.visitLocalVariable("string", "Ljava/lang/String;", null, l82, l4, 12);
		mv.visitLocalVariable("uRLConnection", "Ljava/net/URLConnection;", null, l60, l4, 13);
		mv.visitLocalVariable("bufferedReader", "Ljava/io/BufferedReader;", null, l67, l4, 14);
		mv.visitLocalVariable("nullvar1", "Ljava/lang/Object;", null, l75, l68, 15);
		mv.visitLocalVariable("throwable", "Ljava/lang/Throwable;", null, l83, l54, 10);
		mv.visitLocalVariable("nullvar2", "Ljava/lang/Object;", null, l84, l54, 11);
		mv.visitLocalVariable("nullvar3", "Ljava/lang/Object;", null, l90, l241, 10);
		mv.visitLocalVariable("userID", "Ljava/lang/Object;", null, l91, l241, 11);
		mv.visitLocalVariable("nullvar4", "Ljava/lang/Object;", null, l92, l241, 12);
		mv.visitLocalVariable("md5ID", "Ljava/lang/Object;", null, l6, l241, 13);
		mv.visitLocalVariable("nullvar5", "Ljava/lang/Object;", null, l93, l7, 14);
		mv.visitLocalVariable("digest", "Ljava/security/MessageDigest;", null, l95, l7, 15);
		mv.visitLocalVariable("hash", "[B", null, l98, l7, 16);
		mv.visitLocalVariable("hashHex", "Ljava/lang/StringBuilder;", null, l99, l7, 17);
		mv.visitLocalVariable("arrby", "[B", null, l100, l7, 18);
		mv.visitLocalVariable("n", "I", null, l101, l7, 19);
		mv.visitLocalVariable("n2", "I", null, l102, l7, 20);
		mv.visitLocalVariable("nullvar6", "Ljava/lang/Object;", null, l105, l103, 21);
		mv.visitLocalVariable("aHash", "B", null, l106, l103, 22);
		mv.visitLocalVariable("nullvar7", "Ljava/lang/Object;", null, l111, l7, 21);
		mv.visitLocalVariable("nullvar11", "Ljava/lang/Object;", null, l121, l241, 14);
		mv.visitLocalVariable("sha1ID", "Ljava/lang/Object;", null, l9, l241, 15);
		mv.visitLocalVariable("nullvar8", "Ljava/lang/Object;", null, l122, l10, 16);
		mv.visitLocalVariable("digest", "Ljava/security/MessageDigest;", null, l124, l10, 17);
		mv.visitLocalVariable("hash", "[B", null, l127, l10, 18);
		mv.visitLocalVariable("hashHex", "Ljava/lang/StringBuilder;", null, l128, l10, 19);
		mv.visitLocalVariable("arrby", "[B", null, l129, l10, 20);
		mv.visitLocalVariable("n", "I", null, l130, l10, 21);
		mv.visitLocalVariable("n2", "I", null, l131, l10, 22);
		mv.visitLocalVariable("aHash", "B", null, l134, l132, 23);
		mv.visitLocalVariable("nullvar10", "Ljava/lang/Object;", null, l139, l10, 23);
		mv.visitLocalVariable("nullvar12", "Ljava/lang/Object;", null, l149, l241, 16);
		mv.visitLocalVariable("sha256ID", "Ljava/lang/Object;", null, l12, l241, 17);
		mv.visitLocalVariable("nullvar13", "Ljava/lang/Object;", null, l150, l13, 18);
		mv.visitLocalVariable("digest", "Ljava/security/MessageDigest;", null, l152, l13, 19);
		mv.visitLocalVariable("hash", "[B", null, l155, l13, 20);
		mv.visitLocalVariable("hashHex", "Ljava/lang/StringBuilder;", null, l156, l13, 21);
		mv.visitLocalVariable("arrby", "[B", null, l157, l13, 22);
		mv.visitLocalVariable("n", "I", null, l158, l13, 23);
		mv.visitLocalVariable("n2", "I", null, l159, l13, 24);
		mv.visitLocalVariable("aHash", "B", null, l162, l160, 25);
		mv.visitLocalVariable("nullvar009", "Ljava/lang/Object;", null, l167, l13, 25);
		mv.visitLocalVariable("nullvar16", "Ljava/lang/Object;", null, l177, l241, 18);
		mv.visitLocalVariable("injectedVariable1", "Ljava/lang/Object;", null, l178, l241, 19);
		mv.visitLocalVariable("nullvar17", "Ljava/lang/Object;", null, l179, l241, 20);
		mv.visitLocalVariable("injectedVariable2", "Ljava/lang/Object;", null, l24, l241, 21);
		mv.visitLocalVariable("nullvar18", "Ljava/lang/Object;", null, l180, l26, 22);
		mv.visitLocalVariable("zipFile", "Ljava/util/zip/ZipFile;", null, l183, l26, 23);
		mv.visitLocalVariable("enumeration", "Ljava/util/Enumeration;",
				"Ljava/util/Enumeration<+Ljava/util/zip/ZipEntry;>;", l15, l26, 24);
		mv.visitLocalVariable("nullvar008", "Ljava/lang/Object;", null, l184, l16, 25);
		mv.visitLocalVariable("entry", "Ljava/util/zip/ZipEntry;", null, l187, l185, 26);
		mv.visitLocalVariable("nullvar19", "Ljava/lang/Object;", null, l201, l26, 25);
		mv.visitLocalVariable("object", "Lsun/reflect/ConstantPool;", null, l202, l26, 26);
		mv.visitLocalVariable("constantPoolIsFine", "Z", null, l203, l26, 27);
		mv.visitLocalVariable("i", "I", null, l204, l208, 28);
		mv.visitLocalVariable("mh", "Ljava/lang/invoke/MethodHandle;", null, l209, l26, 28);
		mv.visitLocalVariable("lookup", "Ljava/lang/invoke/MethodHandles$Lookup;", null, l21, l26, 29);
		mv.visitLocalVariable("nullvar006", "Ljava/lang/Object;", null, l210, l22, 30);
		mv.visitLocalVariable("clazz", "Ljava/lang/Class;", null, l211, l22, 31);
		mv.visitLocalVariable("nullvar004", "Ljava/lang/Object;", null, l212, l22, 32);
		mv.visitLocalVariable("currentClassLoader", "Ljava/lang/ClassLoader;", null, l213, l22, 33);
		mv.visitLocalVariable("originalMethodType", "Ljava/lang/invoke/MethodType;", null, l215, l22, 34);
		mv.visitLocalVariable("nullvar4001", "Ljava/lang/Object;", null, l216, l22, 35);
		mv.visitLocalVariable("originalOpcode", "I", null, l217, l22, 36);
		mv.visitLocalVariable("nullvar666", "Ljava/lang/Object;", null, l224, l22, 37);
		mv.visitLocalVariable("ex", "Ljava/lang/Exception;", null, l226, l225, 30);
		mv.visitLocalVariable("nullvar483", "Ljava/lang/Object;", null, l228, l225, 31);
		mv.visitLocalVariable("throwable", "Ljava/lang/Throwable;", null, l229, l240, 22);
		mv.visitLocalVariable("nullvar006", "Ljava/lang/Object;", null, l230, l240, 23);
		mv.visitMaxs(12, 38);
		mv.visitEnd();

		return mv;
	}

	private static MethodNode makeXorMethod() {
		MethodNode method = new MethodNode(ACC_PRIVATE + ACC_STATIC + ACC_SYNTHETIC + ACC_BRIDGE, xorMethodName,
				"(Ljava/lang/String;)Ljava/lang/String;", null, null);
		method.visitCode();
		Label l0 = new Label();
		Label l1 = new Label();
		Label l2 = new Label();
		method.visitTryCatchBlock(l0, l1, l2, "java/lang/Exception");
		method.visitLabel(l0);
		method.visitVarInsn(ALOAD, 0);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
		method.visitVarInsn(ASTORE, 1);
		Label l3 = new Label();
		method.visitLabel(l3);
		method.visitVarInsn(ALOAD, 1);
		method.visitInsn(ARRAYLENGTH);
		method.visitIntInsn(NEWARRAY, T_CHAR);
		method.visitVarInsn(ASTORE, 2);
		Label l4 = new Label();
		method.visitLabel(l4);
		method.visitIntInsn(BIPUSH, 10);
		method.visitIntInsn(NEWARRAY, T_CHAR);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_0);
		method.visitIntInsn(SIPUSH, 18482);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_1);
		method.visitIntInsn(SIPUSH, 9093);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_2);
		method.visitIntInsn(SIPUSH, 9094);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_3);
		method.visitLdcInsn(new Integer(38931));
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_4);
		method.visitLdcInsn(new Integer(37157));
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_5);
		method.visitIntInsn(SIPUSH, 17794);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 6);
		method.visitIntInsn(SIPUSH, 2323);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 7);
		method.visitIntInsn(SIPUSH, 13346);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 8);
		method.visitIntInsn(SIPUSH, 2131);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 9);
		method.visitIntInsn(SIPUSH, 1828);
		method.visitInsn(CASTORE);
		method.visitVarInsn(ASTORE, 3);
		Label l5 = new Label();
		method.visitLabel(l5);
		method.visitIntInsn(BIPUSH, 10);
		method.visitIntInsn(NEWARRAY, T_CHAR);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_0);
		method.visitIntInsn(SIPUSH, 18464);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_1);
		method.visitLdcInsn(new Integer(33795));
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_2);
		method.visitLdcInsn(new Integer(34643));
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_3);
		method.visitIntInsn(SIPUSH, 14338);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_4);
		method.visitIntInsn(SIPUSH, 14400);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_5);
		method.visitIntInsn(SIPUSH, 14484);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 6);
		method.visitLdcInsn(new Integer(34617));
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 7);
		method.visitIntInsn(SIPUSH, 4152);
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 8);
		method.visitLdcInsn(new Integer(33540));
		method.visitInsn(CASTORE);
		method.visitInsn(DUP);
		method.visitIntInsn(BIPUSH, 9);
		method.visitIntInsn(SIPUSH, 13107);
		method.visitInsn(CASTORE);
		method.visitVarInsn(ASTORE, 4);
		Label l6 = new Label();
		method.visitLabel(l6);
		method.visitInsn(ICONST_0);
		method.visitVarInsn(ISTORE, 5);
		Label l7 = new Label();
		method.visitLabel(l7);
		Label l8 = new Label();
		method.visitJumpInsn(GOTO, l8);
		Label l9 = new Label();
		method.visitLabel(l9);
		method.visitFrame(Opcodes.F_FULL, 6,
				new Object[] { "java/lang/String", "[C", "[C", "[C", "[C", Opcodes.INTEGER }, 0, new Object[] {});
		method.visitVarInsn(ALOAD, 2);
		method.visitVarInsn(ILOAD, 5);
		method.visitVarInsn(ALOAD, 1);
		method.visitVarInsn(ILOAD, 5);
		method.visitInsn(CALOAD);
		method.visitVarInsn(ALOAD, 4);
		method.visitVarInsn(ILOAD, 5);
		method.visitVarInsn(ALOAD, 4);
		method.visitInsn(ARRAYLENGTH);
		method.visitInsn(IREM);
		method.visitInsn(CALOAD);
		method.visitInsn(IXOR);
		method.visitInsn(I2C);
		method.visitInsn(CASTORE);
		Label l10 = new Label();
		method.visitLabel(l10);
		method.visitIincInsn(5, 1);
		method.visitLabel(l8);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ILOAD, 5);
		method.visitVarInsn(ALOAD, 1);
		method.visitInsn(ARRAYLENGTH);
		method.visitJumpInsn(IF_ICMPLT, l9);
		Label l11 = new Label();
		method.visitLabel(l11);
		method.visitVarInsn(ALOAD, 2);
		method.visitInsn(ARRAYLENGTH);
		method.visitIntInsn(NEWARRAY, T_CHAR);
		method.visitVarInsn(ASTORE, 5);
		Label l12 = new Label();
		method.visitLabel(l12);
		method.visitInsn(ICONST_0);
		method.visitVarInsn(ISTORE, 6);
		Label l13 = new Label();
		method.visitLabel(l13);
		Label l14 = new Label();
		method.visitJumpInsn(GOTO, l14);
		Label l15 = new Label();
		method.visitLabel(l15);
		method.visitFrame(Opcodes.F_FULL, 7,
				new Object[] { "java/lang/String", "[C", "[C", "[C", "[C", "[C", Opcodes.INTEGER }, 0, new Object[] {});
		method.visitVarInsn(ALOAD, 5);
		method.visitVarInsn(ILOAD, 6);
		method.visitVarInsn(ALOAD, 2);
		method.visitVarInsn(ILOAD, 6);
		method.visitInsn(CALOAD);
		method.visitVarInsn(ALOAD, 3);
		method.visitVarInsn(ILOAD, 6);
		method.visitVarInsn(ALOAD, 3);
		method.visitInsn(ARRAYLENGTH);
		method.visitInsn(IREM);
		method.visitInsn(CALOAD);
		method.visitInsn(IXOR);
		method.visitInsn(I2C);
		method.visitInsn(CASTORE);
		Label l16 = new Label();
		method.visitLabel(l16);
		method.visitIincInsn(6, 1);
		method.visitLabel(l14);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ILOAD, 6);
		method.visitVarInsn(ALOAD, 1);
		method.visitInsn(ARRAYLENGTH);
		method.visitJumpInsn(IF_ICMPLT, l15);
		Label l17 = new Label();
		method.visitLabel(l17);
		method.visitTypeInsn(NEW, "java/lang/String");
		method.visitInsn(DUP);
		method.visitVarInsn(ALOAD, 5);
		method.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
		method.visitLabel(l1);
		method.visitInsn(ARETURN);
		method.visitLabel(l2);
		method.visitFrame(Opcodes.F_FULL, 1, new Object[] { "java/lang/String" }, 1,
				new Object[] { "java/lang/Exception" });
		method.visitVarInsn(ASTORE, 1);
		Label l18 = new Label();
		method.visitLabel(l18);
		method.visitVarInsn(ALOAD, 0);
		method.visitInsn(ARETURN);
		Label l19 = new Label();
		method.visitLabel(l19);
		method.visitMaxs(6, 7);
		method.visitEnd();

		return method;
	}

	private static MethodNode makeJava6Method(String className, String link, String resourceId, String userId,
			String nonceId) {
		MethodNode method = new MethodNode(ACC_PRIVATE + ACC_STATIC + ACC_SYNTHETIC + ACC_BRIDGE, java6MethodName,
				"()V", null, null);

		method.visitCode();
		Label l0 = new Label();
		Label l1 = new Label();
		Label l2 = new Label();
		method.visitTryCatchBlock(l0, l1, l2, "java/lang/Throwable");
		Label l3 = new Label();
		Label l4 = new Label();
		Label l5 = new Label();
		method.visitTryCatchBlock(l3, l4, l5, "java/lang/Throwable");
		Label l6 = new Label();
		Label l7 = new Label();
		Label l8 = new Label();
		method.visitTryCatchBlock(l6, l7, l8, "java/lang/Throwable");
		Label l9 = new Label();
		Label l10 = new Label();
		Label l11 = new Label();
		method.visitTryCatchBlock(l9, l10, l11, "java/lang/Throwable");
		Label l12 = new Label();
		Label l13 = new Label();
		Label l14 = new Label();
		method.visitTryCatchBlock(l12, l13, l14, "java/lang/Throwable");
		Label l15 = new Label();
		Label l16 = new Label();
		Label l17 = new Label();
		method.visitTryCatchBlock(l15, l16, l17, "java/lang/Throwable");
		method.visitLabel(l0);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 0);
		Label l18 = new Label();
		method.visitLabel(l18);
		method.visitTypeInsn(NEW, "java/net/URL");
		method.visitInsn(DUP);
		method.visitLdcInsn(Injector.xor(link));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKESPECIAL, "java/net/URL", "<init>", "(Ljava/lang/String;)V", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/net/URL", "openConnection", "()Ljava/net/URLConnection;", false);
		method.visitVarInsn(ASTORE, 2);
		Label l19 = new Label();
		method.visitLabel(l19);
		method.visitVarInsn(ALOAD, 2);
		method.visitInsn(ICONST_3);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "setConnectTimeout", "(I)V", false);
		Label l20 = new Label();
		method.visitLabel(l20);
		method.visitVarInsn(ALOAD, 2);
		method.visitInsn(ICONST_3);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "setReadTimeout", "(I)V", false);
		Label l21 = new Label();
		method.visitLabel(l21);
		method.visitTypeInsn(NEW, "java/io/BufferedReader");
		method.visitInsn(DUP);
		method.visitTypeInsn(NEW, "java/io/InputStreamReader");
		method.visitInsn(DUP);
		method.visitVarInsn(ALOAD, 2);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/net/URLConnection", "getInputStream", "()Ljava/io/InputStream;",
				false);
		method.visitMethodInsn(INVOKESPECIAL, "java/io/InputStreamReader", "<init>", "(Ljava/io/InputStream;)V", false);
		method.visitMethodInsn(INVOKESPECIAL, "java/io/BufferedReader", "<init>", "(Ljava/io/Reader;)V", false);
		method.visitVarInsn(ASTORE, 3);
		Label l22 = new Label();
		method.visitLabel(l22);
		Label l23 = new Label();
		method.visitJumpInsn(GOTO, l23);
		Label l24 = new Label();
		method.visitLabel(l24);
		method.visitFrame(Opcodes.F_FULL, 4, new Object[] { "java/lang/Object", "java/lang/String",
				"java/net/URLConnection", "java/io/BufferedReader" }, 0, new Object[] {});
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 4);
		Label l25 = new Label();
		method.visitLabel(l25);
		method.visitVarInsn(ALOAD, 1);
		method.visitLdcInsn(Injector.xor(userId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l26 = new Label();
		method.visitJumpInsn(IFNE, l26);
		method.visitJumpInsn(GOTO, l23);
		method.visitLabel(l26);
		method.visitFrame(Opcodes.F_APPEND, 1, new Object[] { "java/lang/Object" }, 0, null);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Your account on InfiniteLeaks has been Banned!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l27 = new Label();
		method.visitLabel(l27);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please download the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l28 = new Label();
		method.visitLabel(l28);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x0"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l29 = new Label();
		method.visitLabel(l29);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l23);
		method.visitFrame(Opcodes.F_FULL, 4,
				new Object[] { "java/lang/Object", Opcodes.TOP, "java/net/URLConnection", "java/io/BufferedReader" }, 0,
				new Object[] {});
		method.visitVarInsn(ALOAD, 3);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/BufferedReader", "readLine", "()Ljava/lang/String;", false);
		method.visitInsn(DUP);
		method.visitVarInsn(ASTORE, 1);
		Label l30 = new Label();
		method.visitLabel(l30);
		method.visitJumpInsn(IFNONNULL, l24);
		method.visitLabel(l1);
		Label l31 = new Label();
		method.visitJumpInsn(GOTO, l31);
		method.visitLabel(l2);
		method.visitFrame(Opcodes.F_FULL, 0, new Object[] {}, 1, new Object[] { "java/lang/Throwable" });
		method.visitVarInsn(ASTORE, 0);
		Label l32 = new Label();
		method.visitLabel(l32);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 1);
		Label l35 = new Label();
		method.visitLabel(l35);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l31);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 0);
		Label l36 = new Label();
		method.visitLabel(l36);
		method.visitLdcInsn(Injector.xor(userId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitVarInsn(ASTORE, 1);
		Label l37 = new Label();
		method.visitLabel(l37);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 2);
		Label l38 = new Label();
		method.visitLabel(l38);
		method.visitLdcInsn(Injector.xor(Injector.getHash("MD5", userId)));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitVarInsn(ASTORE, 3);
		method.visitLabel(l3);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 4);
		Label l39 = new Label();
		method.visitLabel(l39);
		method.visitLdcInsn(Injector.xor("MD5"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance",
				"(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
		method.visitVarInsn(ASTORE, 5);
		Label l40 = new Label();
		method.visitLabel(l40);
		method.visitVarInsn(ALOAD, 5);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "reset", "()V", false);
		Label l41 = new Label();
		method.visitLabel(l41);
		method.visitVarInsn(ALOAD, 5);
		method.visitVarInsn(ALOAD, 1);
		method.visitTypeInsn(CHECKCAST, "java/lang/String");
		method.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "update", "([B)V", false);
		Label l42 = new Label();
		method.visitLabel(l42);
		method.visitVarInsn(ALOAD, 5);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "()[B", false);
		method.visitVarInsn(ASTORE, 6);
		Label l43 = new Label();
		method.visitLabel(l43);
		method.visitTypeInsn(NEW, "java/lang/StringBuilder");
		method.visitInsn(DUP);
		method.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
		method.visitVarInsn(ASTORE, 7);
		Label l44 = new Label();
		method.visitLabel(l44);
		method.visitVarInsn(ALOAD, 6);
		method.visitVarInsn(ASTORE, 8);
		Label l45 = new Label();
		method.visitLabel(l45);
		method.visitVarInsn(ALOAD, 8);
		method.visitInsn(ARRAYLENGTH);
		method.visitVarInsn(ISTORE, 9);
		Label l46 = new Label();
		method.visitLabel(l46);
		method.visitInsn(ICONST_0);
		method.visitVarInsn(ISTORE, 10);
		Label l47 = new Label();
		method.visitLabel(l47);
		Label l48 = new Label();
		method.visitJumpInsn(GOTO, l48);
		Label l49 = new Label();
		method.visitLabel(l49);
		method.visitFrame(Opcodes.F_FULL, 11,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/security/MessageDigest", "[B", "java/lang/StringBuilder", "[B",
						Opcodes.INTEGER, Opcodes.INTEGER },
				0, new Object[] {});
		method.visitVarInsn(ALOAD, 8);
		method.visitVarInsn(ILOAD, 10);
		method.visitInsn(BALOAD);
		method.visitVarInsn(ISTORE, 11);
		Label l50 = new Label();
		method.visitLabel(l50);
		method.visitVarInsn(ALOAD, 7);
		method.visitVarInsn(ILOAD, 11);
		method.visitIntInsn(SIPUSH, 255);
		method.visitInsn(IAND);
		method.visitIntInsn(SIPUSH, 256);
		method.visitInsn(IADD);
		method.visitIntInsn(BIPUSH, 16);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toString", "(II)Ljava/lang/String;", false);
		method.visitInsn(ICONST_1);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "substring", "(I)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		method.visitInsn(POP);
		Label l51 = new Label();
		method.visitLabel(l51);
		method.visitIincInsn(10, 1);
		method.visitLabel(l48);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ILOAD, 10);
		method.visitVarInsn(ILOAD, 9);
		method.visitJumpInsn(IF_ICMPLT, l49);
		Label l52 = new Label();
		method.visitLabel(l52);
		method.visitVarInsn(ALOAD, 7);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		method.visitVarInsn(ALOAD, 3);
		method.visitTypeInsn(CHECKCAST, "java/lang/String");
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z", false);
		Label l53 = new Label();
		method.visitJumpInsn(IFNE, l53);
		Label l54 = new Label();
		method.visitLabel(l54);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 11);
		Label l55 = new Label();
		method.visitLabel(l55);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] File tampering detected!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l56 = new Label();
		method.visitLabel(l56);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please redownload the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l57 = new Label();
		method.visitLabel(l57);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x2"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l58 = new Label();
		method.visitLabel(l58);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l4);
		method.visitJumpInsn(GOTO, l53);
		method.visitLabel(l5);
		method.visitFrame(Opcodes.F_FULL, 4,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object" }, 1,
				new Object[] { "java/lang/Throwable" });
		method.visitVarInsn(ASTORE, 4);
		method.visitLabel(l53);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 4);
		Label l59 = new Label();
		method.visitLabel(l59);
		method.visitLdcInsn(Injector.xor(Injector.getHash("SHA-1", userId)));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitVarInsn(ASTORE, 5);
		method.visitLabel(l6);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 6);
		Label l60 = new Label();
		method.visitLabel(l60);
		method.visitLdcInsn(Injector.xor("SHA-1"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance",
				"(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
		method.visitVarInsn(ASTORE, 7);
		Label l61 = new Label();
		method.visitLabel(l61);
		method.visitVarInsn(ALOAD, 7);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "reset", "()V", false);
		Label l62 = new Label();
		method.visitLabel(l62);
		method.visitVarInsn(ALOAD, 7);
		method.visitVarInsn(ALOAD, 1);
		method.visitTypeInsn(CHECKCAST, "java/lang/String");
		method.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "update", "([B)V", false);
		Label l63 = new Label();
		method.visitLabel(l63);
		method.visitVarInsn(ALOAD, 7);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "()[B", false);
		method.visitVarInsn(ASTORE, 8);
		Label l64 = new Label();
		method.visitLabel(l64);
		method.visitTypeInsn(NEW, "java/lang/StringBuilder");
		method.visitInsn(DUP);
		method.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
		method.visitVarInsn(ASTORE, 9);
		Label l65 = new Label();
		method.visitLabel(l65);
		method.visitVarInsn(ALOAD, 8);
		method.visitVarInsn(ASTORE, 10);
		Label l66 = new Label();
		method.visitLabel(l66);
		method.visitVarInsn(ALOAD, 10);
		method.visitInsn(ARRAYLENGTH);
		method.visitVarInsn(ISTORE, 11);
		Label l67 = new Label();
		method.visitLabel(l67);
		method.visitInsn(ICONST_0);
		method.visitVarInsn(ISTORE, 12);
		Label l68 = new Label();
		method.visitLabel(l68);
		Label l69 = new Label();
		method.visitJumpInsn(GOTO, l69);
		Label l70 = new Label();
		method.visitLabel(l70);
		method.visitFrame(Opcodes.F_FULL, 13,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/security/MessageDigest", "[B",
						"java/lang/StringBuilder", "[B", Opcodes.INTEGER, Opcodes.INTEGER },
				0, new Object[] {});
		method.visitVarInsn(ALOAD, 10);
		method.visitVarInsn(ILOAD, 12);
		method.visitInsn(BALOAD);
		method.visitVarInsn(ISTORE, 13);
		Label l71 = new Label();
		method.visitLabel(l71);
		method.visitVarInsn(ALOAD, 9);
		method.visitVarInsn(ILOAD, 13);
		method.visitIntInsn(SIPUSH, 255);
		method.visitInsn(IAND);
		method.visitIntInsn(SIPUSH, 256);
		method.visitInsn(IADD);
		method.visitIntInsn(BIPUSH, 16);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toString", "(II)Ljava/lang/String;", false);
		method.visitInsn(ICONST_1);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "substring", "(I)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		method.visitInsn(POP);
		Label l72 = new Label();
		method.visitLabel(l72);
		method.visitIincInsn(12, 1);
		method.visitLabel(l69);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ILOAD, 12);
		method.visitVarInsn(ILOAD, 11);
		method.visitJumpInsn(IF_ICMPLT, l70);
		Label l73 = new Label();
		method.visitLabel(l73);
		method.visitVarInsn(ALOAD, 9);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		method.visitVarInsn(ALOAD, 5);
		method.visitTypeInsn(CHECKCAST, "java/lang/String");
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z", false);
		Label l74 = new Label();
		method.visitJumpInsn(IFNE, l74);
		Label l75 = new Label();
		method.visitLabel(l75);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 13);
		Label l76 = new Label();
		method.visitLabel(l76);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] File tampering detected!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l77 = new Label();
		method.visitLabel(l77);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please redownload the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l78 = new Label();
		method.visitLabel(l78);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x2"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l79 = new Label();
		method.visitLabel(l79);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l7);
		method.visitJumpInsn(GOTO, l74);
		method.visitLabel(l8);
		method.visitFrame(
				Opcodes.F_FULL, 6, new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Throwable" });
		method.visitVarInsn(ASTORE, 6);
		method.visitLabel(l74);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 6);
		Label l80 = new Label();
		method.visitLabel(l80);
		method.visitLdcInsn(Injector.xor(Injector.getHash("SHA-256", userId)));
		method.visitVarInsn(ASTORE, 7);
		method.visitLabel(l9);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 8);
		Label l81 = new Label();
		method.visitLabel(l81);
		method.visitLdcInsn(Injector.xor("SHA-256"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKESTATIC, "java/security/MessageDigest", "getInstance",
				"(Ljava/lang/String;)Ljava/security/MessageDigest;", false);
		method.visitVarInsn(ASTORE, 9);
		Label l82 = new Label();
		method.visitLabel(l82);
		method.visitVarInsn(ALOAD, 9);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "reset", "()V", false);
		Label l83 = new Label();
		method.visitLabel(l83);
		method.visitVarInsn(ALOAD, 9);
		method.visitVarInsn(ALOAD, 1);
		method.visitTypeInsn(CHECKCAST, "java/lang/String");
		method.visitFieldInsn(GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;");
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/nio/charset/Charset;)[B", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "update", "([B)V", false);
		Label l84 = new Label();
		method.visitLabel(l84);
		method.visitVarInsn(ALOAD, 9);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/MessageDigest", "digest", "()[B", false);
		method.visitVarInsn(ASTORE, 10);
		Label l85 = new Label();
		method.visitLabel(l85);
		method.visitTypeInsn(NEW, "java/lang/StringBuilder");
		method.visitInsn(DUP);
		method.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
		method.visitVarInsn(ASTORE, 11);
		Label l86 = new Label();
		method.visitLabel(l86);
		method.visitVarInsn(ALOAD, 10);
		method.visitVarInsn(ASTORE, 12);
		Label l87 = new Label();
		method.visitLabel(l87);
		method.visitVarInsn(ALOAD, 12);
		method.visitInsn(ARRAYLENGTH);
		method.visitVarInsn(ISTORE, 13);
		Label l88 = new Label();
		method.visitLabel(l88);
		method.visitInsn(ICONST_0);
		method.visitVarInsn(ISTORE, 14);
		Label l89 = new Label();
		method.visitLabel(l89);
		Label l90 = new Label();
		method.visitJumpInsn(GOTO, l90);
		Label l91 = new Label();
		method.visitLabel(l91);
		method.visitFrame(Opcodes.F_FULL, 15,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/security/MessageDigest", "[B", "java/lang/StringBuilder", "[B",
						Opcodes.INTEGER, Opcodes.INTEGER },
				0, new Object[] {});
		method.visitVarInsn(ALOAD, 12);
		method.visitVarInsn(ILOAD, 14);
		method.visitInsn(BALOAD);
		method.visitVarInsn(ISTORE, 15);
		Label l92 = new Label();
		method.visitLabel(l92);
		method.visitVarInsn(ALOAD, 11);
		method.visitVarInsn(ILOAD, 15);
		method.visitIntInsn(SIPUSH, 255);
		method.visitInsn(IAND);
		method.visitIntInsn(SIPUSH, 256);
		method.visitInsn(IADD);
		method.visitIntInsn(BIPUSH, 16);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "toString", "(II)Ljava/lang/String;", false);
		method.visitInsn(ICONST_1);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "substring", "(I)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
				"(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
		method.visitInsn(POP);
		Label l93 = new Label();
		method.visitLabel(l93);
		method.visitIincInsn(14, 1);
		method.visitLabel(l90);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ILOAD, 14);
		method.visitVarInsn(ILOAD, 13);
		method.visitJumpInsn(IF_ICMPLT, l91);
		Label l94 = new Label();
		method.visitLabel(l94);
		method.visitVarInsn(ALOAD, 11);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
		method.visitVarInsn(ALOAD, 7);
		method.visitTypeInsn(CHECKCAST, "java/lang/String");
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equalsIgnoreCase", "(Ljava/lang/String;)Z", false);
		Label l95 = new Label();
		method.visitJumpInsn(IFNE, l95);
		Label l96 = new Label();
		method.visitLabel(l96);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 15);
		Label l97 = new Label();
		method.visitLabel(l97);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] File tampering detected!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l98 = new Label();
		method.visitLabel(l98);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please redownload the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l99 = new Label();
		method.visitLabel(l99);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x2"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l100 = new Label();
		method.visitLabel(l100);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l10);
		method.visitJumpInsn(GOTO, l95);
		method.visitLabel(l11);
		method.visitFrame(Opcodes.F_FULL, 8,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Throwable" });
		method.visitVarInsn(ASTORE, 8);
		method.visitLabel(l95);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 8);
		Label l101 = new Label();
		method.visitLabel(l101);
		method.visitFieldInsn(GETSTATIC, className, fakeBooleanName, "I");
		method.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
		method.visitVarInsn(ASTORE, 9);
		Label l102 = new Label();
		method.visitLabel(l102);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 10);
		Label l103 = new Label();
		method.visitLabel(l103);
		method.visitFieldInsn(GETSTATIC, className, statusCheckName, "Ljava/lang/String;");
		method.visitVarInsn(ASTORE, 11);
		method.visitLabel(l15);
		method.visitTypeInsn(NEW, "java/util/zip/ZipFile");
		method.visitInsn(DUP);
		method.visitTypeInsn(NEW, "java/io/File");
		method.visitInsn(DUP);
		method.visitLdcInsn(Type.getType("L" + className + ";.class"));
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getProtectionDomain",
				"()Ljava/security/ProtectionDomain;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/ProtectionDomain", "getCodeSource",
				"()Ljava/security/CodeSource;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/security/CodeSource", "getLocation", "()Ljava/net/URL;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/net/URL", "toURI", "()Ljava/net/URI;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/net/URI", "getPath", "()Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
		method.visitMethodInsn(INVOKESPECIAL, "java/util/zip/ZipFile", "<init>", "(Ljava/io/File;)V", false);
		method.visitVarInsn(ASTORE, 12);
		Label l104 = new Label();
		method.visitLabel(l104);
		method.visitVarInsn(ALOAD, 12);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipFile", "entries", "()Ljava/util/Enumeration;", false);
		method.visitVarInsn(ASTORE, 13);
		method.visitLabel(l12);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 14);
		Label l105 = new Label();
		method.visitLabel(l105);
		Label l106 = new Label();
		method.visitJumpInsn(GOTO, l106);
		Label l107 = new Label();
		method.visitLabel(l107);
		method.visitFrame(Opcodes.F_FULL, 15,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/util/zip/ZipFile", "java/util/Enumeration", "java/lang/Object" },
				0, new Object[] {});
		method.visitVarInsn(ALOAD, 13);
		method.visitMethodInsn(INVOKEINTERFACE, "java/util/Enumeration", "nextElement", "()Ljava/lang/Object;", true);
		method.visitTypeInsn(CHECKCAST, "java/util/zip/ZipEntry");
		method.visitVarInsn(ASTORE, 15);
		Label l108 = new Label();
		method.visitLabel(l108);
		method.visitVarInsn(ALOAD, 15);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipEntry", "getLastAccessTime",
				"()Ljava/nio/file/attribute/FileTime;", false);
		Label l109 = new Label();
		method.visitJumpInsn(IFNONNULL, l109);
		method.visitVarInsn(ALOAD, 15);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipEntry", "getCreationTime",
				"()Ljava/nio/file/attribute/FileTime;", false);
		method.visitJumpInsn(IFNONNULL, l109);
		method.visitJumpInsn(GOTO, l106);
		method.visitLabel(l109);
		method.visitFrame(Opcodes.F_APPEND, 1, new Object[] { "java/util/zip/ZipEntry" }, 0, null);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] File tampering detected!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l110 = new Label();
		method.visitLabel(l110);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please redownload the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l111 = new Label();
		method.visitLabel(l111);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x2"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l112 = new Label();
		method.visitLabel(l112);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l106);
		method.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
		method.visitVarInsn(ALOAD, 13);
		method.visitMethodInsn(INVOKEINTERFACE, "java/util/Enumeration", "hasMoreElements", "()Z", true);
		method.visitJumpInsn(IFNE, l107);
		method.visitLabel(l13);
		Label l113 = new Label();
		method.visitJumpInsn(GOTO, l113);
		method.visitLabel(l14);
		method.visitFrame(Opcodes.F_FULL, 14,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/util/zip/ZipFile", "java/util/Enumeration" },
				1, new Object[] { "java/lang/Throwable" });
		method.visitVarInsn(ASTORE, 14);
		method.visitLabel(l113);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ALOAD, 12);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/util/zip/ZipFile", "close", "()V", false);
		Label l114 = new Label();
		method.visitLabel(l114);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 14);
		Label l115 = new Label();
		method.visitLabel(l115);
		method.visitMethodInsn(INVOKESTATIC, "sun/misc/SharedSecrets", "getJavaLangAccess",
				"()Lsun/misc/JavaLangAccess;", false);
		method.visitLdcInsn(Type.getType("L" + className + ";.class"));
		method.visitMethodInsn(INVOKEINTERFACE, "sun/misc/JavaLangAccess", "getConstantPool",
				"(Ljava/lang/Class;)Lsun/reflect/ConstantPool;", true);
		method.visitVarInsn(ASTORE, 15);
		Label l116 = new Label();
		method.visitLabel(l116);
		method.visitInsn(ICONST_0);
		method.visitVarInsn(ISTORE, 16);
		Label l117 = new Label();
		method.visitLabel(l117);
		Label l118 = new Label();
		method.visitJumpInsn(GOTO, l118);
		Label l119 = new Label();
		method.visitLabel(l119);
		method.visitFrame(Opcodes.F_APPEND, 3,
				new Object[] { "java/lang/Object", "sun/reflect/ConstantPool", Opcodes.INTEGER }, 0, null);
		method.visitVarInsn(ALOAD, 15);
		method.visitVarInsn(ILOAD, 16);
		method.visitMethodInsn(INVOKEVIRTUAL, "sun/reflect/ConstantPool", "getUTF8At", "(I)Ljava/lang/String;", false);
		method.visitTypeInsn(NEW, "java/lang/String");
		method.visitInsn(DUP);
		method.visitInsn(ICONST_5);
		method.visitIntInsn(NEWARRAY, T_BYTE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_0);
		method.visitIntInsn(BIPUSH, 66);
		method.visitInsn(BASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_1);
		method.visitIntInsn(BIPUSH, 76);
		method.visitInsn(BASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_2);
		method.visitIntInsn(BIPUSH, 79);
		method.visitInsn(BASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_3);
		method.visitIntInsn(BIPUSH, 82);
		method.visitInsn(BASTORE);
		method.visitInsn(DUP);
		method.visitInsn(ICONST_4);
		method.visitIntInsn(BIPUSH, 71);
		method.visitInsn(BASTORE);
		method.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([B)V", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
		Label l120 = new Label();
		method.visitJumpInsn(IFEQ, l120);
		Label l121 = new Label();
		method.visitLabel(l121);
		Label l122 = new Label();
		method.visitJumpInsn(GOTO, l122);
		method.visitLabel(l120);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitIincInsn(16, 1);
		method.visitLabel(l118);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitVarInsn(ILOAD, 16);
		method.visitVarInsn(ALOAD, 15);
		method.visitMethodInsn(INVOKEVIRTUAL, "sun/reflect/ConstantPool", "getSize", "()I", false);
		method.visitJumpInsn(IF_ICMPLT, l119);
		method.visitLabel(l122);
		method.visitFrame(Opcodes.F_CHOP, 1, null, 0, null);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] File tampering detected!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l123 = new Label();
		method.visitLabel(l123);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please redownload the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l124 = new Label();
		method.visitLabel(l124);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x2"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l125 = new Label();
		method.visitLabel(l125);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
		method.visitLabel(l16);
		Label l126 = new Label();
		method.visitJumpInsn(GOTO, l126);
		method.visitLabel(l17);
		method.visitFrame(Opcodes.F_FULL, 12,
				new Object[] { "java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object",
						"java/lang/Object", "java/lang/Object", "java/lang/Object", "java/lang/Object" },
				1, new Object[] { "java/lang/Throwable" });
		method.visitVarInsn(ASTORE, 12);
		Label l127 = new Label();
		method.visitLabel(l127);
		method.visitInsn(ACONST_NULL);
		method.visitVarInsn(ASTORE, 13);
		Label l128 = new Label();
		method.visitLabel(l128);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] File tampering detected!"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l129 = new Label();
		method.visitLabel(l129);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor(
				"[InfiniteLeaks] Please redownload the file from https://InfiniteLeaks.net/resources/" + resourceId));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l130 = new Label();
		method.visitLabel(l130);
		method.visitFieldInsn(GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
		method.visitLdcInsn(Injector.xor("[InfiniteLeaks] Error code: 0x2"));
		method.visitMethodInsn(INVOKESTATIC, className, xorMethodName, "(Ljava/lang/String;)Ljava/lang/String;", false);
		method.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
		Label l131 = new Label();
		method.visitLabel(l131);
		method.visitInsn(ICONST_0);
		method.visitMethodInsn(INVOKESTATIC, "java/lang/System", "exitf", "(I)V", false);
		method.visitLabel(l126);
		method.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
		method.visitInsn(RETURN);
		Label l132 = new Label();
		method.visitLabel(l132);
		method.visitMaxs(7, 17);
		method.visitEnd();

		return method;
	}

	public static void main(String[] args) throws Exception {
		ClassWriter cw = new ClassWriter(0);

		cw.visit(V1_6, ACC_PUBLIC + ACC_SUPER, "sample/HelloGen", null, "java/lang/Object", null);

	}

	private static void writeToOut(ZipOutputStream outputStream, InputStream inputStream) throws Throwable {
		byte[] buffer = new byte[4096];
		try {
			while (inputStream.available() > 0) {
				int data = inputStream.read(buffer);
				outputStream.write(buffer, 0, data);
			}
		} finally {
			inputStream.close();
			outputStream.closeEntry();
		}
	}

	private static String generateNonceId() {
		return String.valueOf(Injector.randomString(10).hashCode());
	}

	private static InsnList copyInsnList(InsnList original) {
		InsnList insnList = new InsnList();
		int i = 0;
		while (i < original.size()) {
			insnList.add(original.get(i));
			++i;
		}
		return insnList;
	}

	private static String getHash(String algorithm, String content) {
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithm);
			digest.reset();
			digest.update(content.getBytes(StandardCharsets.UTF_8));
			byte[] hash = digest.digest();
			StringBuilder hashHex = new StringBuilder();
			byte[] arrby = hash;
			int n = arrby.length;
			int n2 = 0;
			while (n2 < n) {
				byte aHash = arrby[n2];
				hashHex.append(Integer.toString((aHash & 255) + 256, 16).substring(1));
				++n2;
			}
			return hashHex.toString();
		} catch (Throwable t) {
			t.printStackTrace();
			return content;
		}
	}

	private static String randomString(int length) {
		char[] CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
		StringBuilder result = new StringBuilder();
		while (result.length() < length) {
			int index = (int) (Injector.getRandom().nextFloat() * (float) CHARSET.length);
			result.append(CHARSET[index]);
		}
		return result.toString();
	}

	private static Random getRandom() {
		return ThreadLocalRandom.current();
	}

	private static String replacePlaceholders(String original, Info info) {
		return original.replace("%%__USER__%%", info.getUserId()).replace("%%__NONCE__%%", Injector.generateNonceId())
				.replace("%%__RESOURCE__%%", info.getResourceId()).replace("%%__RANDOM__%%", Injector.randomString(10))
				.replace("%%__MD5ID__%%", Injector.getHash("MD5", info.userId))
				.replace("%%__SHA-256ID__%%", Injector.getHash("SHA-256", info.userId))
				.replace("%%__SHA-1ID__%%", Injector.getHash("SHA-1", info.userId))
				.replace("%%__TIME__%%", String.valueOf(System.currentTimeMillis()))
				.replace("%%__XORID__%%", Injector.xor(info.getUserId()))
				.replace("%%__USER2__%%", String.valueOf(Integer.valueOf(info.getUserId()) + 66837767))
				.replace("%%__DATE__%%", Injector.getDate());
	}

	private static boolean containPlaceHolder(String content) {
		for (String s : PLACEHOLDERS) {
			if (!content.contains(s))
				continue;
			return true;
		}
		return false;
	}

	private static String getDate() {
		Date today = Calendar.getInstance().getTime();
		SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy-hh:mm:ss.SSS-z");
		String date = formatter.format(today);
		return date;
	}

	private static String xor(String message) {
		try {
			char[] messageChars = ((String) message).toCharArray();
			char[] newMessage = new char[messageChars.length];
			char[] XORKEY = new char[] { '\u4832', '\u2385', '\u2386', '\u9813', '\u9125', '\u4582', '\u0913', '\u3422',
					'\u0853', '\u0724' };
			char[] XORKEY2 = new char[] { '\u4820', '\u8403', '\u8753', '\u3802', '\u3840', '\u3894', '\u8739',
					'\u1038', '\u8304', '\u3333' };
			for (int j = 0; j < messageChars.length; ++j) {
				newMessage[j] = (char) (messageChars[j] ^ XORKEY[j % XORKEY.length]);
			}
			char[] decryptedmsg = new char[newMessage.length];
			for (int j = 0; j < messageChars.length; ++j) {
				decryptedmsg[j] = (char) (newMessage[j] ^ XORKEY2[j % XORKEY2.length]);
			}
			return new String(decryptedmsg);
		} catch (Exception ignore) {
			return message;
		}
	}

	public class Info {
		private String userId;
		private String resourceId;

		public Info(String userId, String resourceId) {
			this.userId = userId;
			this.resourceId = resourceId;
		}

		public String getUserId() {
			return this.userId;
		}

		public String getResourceId() {
			return this.resourceId;
		}
	}

}