import jdk.jfr.Event;
import java.util.concurrent.BrokenBarrierException;
import java.io.InputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;

/*
 * @test
 * @bug 8251945
 * @requires (os.arch != "s390x" | jdk.version.major > 8)
 * @summary JDK-8251945 SIGSEGV in PackageEntry::purge_qualified_exports()
 * @run main/othervm/fail PredefinedClassloaderCyclicBarrierCrash
 */
public final class PredefinedClassloaderCyclicBarrierCrash
{
    private volatile ClassLoader nextLoader;
    
    public static void main(final String[] args) throws Exception {
        new PredefinedClassloaderCyclicBarrierCrash().crash();
        Thread.sleep(10000);
        throw new Exception("pass");
    }
    
    public void crash() {
        System.out.println("Start");
        final byte[] runnableClass = loadBytecode("PredefinedClassloaderCyclicBarrierCrash$TestRunnable");
        final byte[] eventClass = loadBytecode("PredefinedClassloaderCyclicBarrierCrash$TestRunnable$RunnableEvent");
        final int numberOfThreads = Runtime.getRuntime().availableProcessors();
        if (numberOfThreads < 1) {
            throw new IllegalStateException("requies more than one thread");
        }
        final ExecutorService threadPool = Executors.newFixedThreadPool(numberOfThreads);
        final CyclicBarrier cyclicBarrier = new CyclicBarrier(numberOfThreads, () -> this.nextLoader = new PredefinedClassLoader(runnableClass, eventClass));
        for (int i = 0; i < numberOfThreads; ++i) {
            threadPool.submit(new LoadingRunnable(cyclicBarrier));
        }
        threadPool.shutdown();
        System.out.println("Stop");
    }
    
    Runnable loadTestRunnable(final ClassLoader classLoader) {
        try {
            return (Runnable)Class.forName("PredefinedClassloaderCyclicBarrierCrash$TestRunnable", true, classLoader).asSubclass(Runnable.class).getConstructor((Class<?>[])new Class[0]).newInstance(new Object[0]);
        }
        catch (ReflectiveOperationException e) {
            throw new RuntimeException("could not load runnable", e);
        }
    }
    
    private static byte[] loadBytecode(final String className) {
        final String resource = toResourceName(className);
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            final InputStream inputStream = PredefinedClassloaderCyclicBarrierCrash.class.getClassLoader().getResourceAsStream(resource);
            try {
//                inputStream.transferTo(buffer);
    int length;
    byte[] bytes = new byte[1024];
    while ((length = inputStream.read(bytes)) != -1) {
        buffer.write(bytes, 0, length);
    }
                if (inputStream != null) {
                    inputStream.close();
                }
            }
            catch (Throwable t) {
                if (inputStream != null) {
                    try {
                        inputStream.close();
                    }
                    catch (Throwable exception) {
                        t.addSuppressed(exception);
                    }
                }
                throw t;
            }
        }
        catch (IOException e) {
            throw new UncheckedIOException(className, e);
        }
        return buffer.toByteArray();
    }
    
    private static String toResourceName(final String className) {
        return className.replace('.', '/') + ".class";
    }
    
    final class LoadingRunnable implements Runnable
    {
        private final CyclicBarrier barrier;
        
        LoadingRunnable(final CyclicBarrier barrier) {
            this.barrier = barrier;
        }
        
        @Override
        public void run() {
            try {
                while (true) {
                    this.barrier.await();
                    final Runnable runnable = PredefinedClassloaderCyclicBarrierCrash.this.loadTestRunnable(PredefinedClassloaderCyclicBarrierCrash.this.nextLoader);
                    runnable.run();
                }
            }
            catch (InterruptedException | BrokenBarrierException ex) {
                final Exception e = ex;
            }
        }
    }
    
    static final class PredefinedClassLoader extends ClassLoader
    {
        private final byte[] runnableClass;
        private final byte[] eventClass;

        PredefinedClassLoader(final byte[] runnableClass, final byte[] eventClass) {
            super(null);
            this.runnableClass = runnableClass;
            this.eventClass = eventClass;
        }
        
        @Override
        protected Class<?> loadClass(final String className, final boolean resolve) throws ClassNotFoundException {
            final Class<?> loadedClass = this.findLoadedClass(className);
            if (loadedClass != null) {
                if (resolve) {
                    this.resolveClass(loadedClass);
                }
                return loadedClass;
            }
            if (className.equals("PredefinedClassloaderCyclicBarrierCrash$TestRunnable")) {
                return this.loadClassFromByteArray(className, resolve, this.runnableClass);
            }
            if (className.equals("PredefinedClassloaderCyclicBarrierCrash$TestRunnable$RunnableEvent")) {
                return this.loadClassFromByteArray(className, resolve, this.eventClass);
            }
            return super.loadClass(className, resolve);
        }

        private Class<?> loadClassFromByteArray(final String className, final boolean resolve, final byte[] byteCode) throws ClassNotFoundException {
            Class<?> clazz;
            try {
                synchronized (getClassLoadingLock(className)) {
                    clazz = this.defineClass(className, byteCode, 0, byteCode.length);
                }
            }
            catch (LinkageError e) {
                clazz = this.findLoadedClass(className);
            }
            if (resolve) {
                this.resolveClass(clazz);
            }
            return clazz;
        }
    }

    public static final class TestRunnable implements Runnable
    {
        @Override
        public void run() {
            final RunnableEvent event = new RunnableEvent();
            event.setRunnableClassName("TestRunnable");
            event.begin();
            event.end();
            event.commit();
        }
        
        public static class RunnableEvent extends Event
        {
            private String runnableClassName;
            
            String getRunnableClassName() {
                return this.runnableClassName;
            }
            
            void setRunnableClassName(final String operationName) {
                this.runnableClassName = operationName;
            }
        }
    }
}
    
