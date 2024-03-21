package com.org.shell_elf;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import com.org.shell_elf.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'shell_elf' library on application startup.
    static {
        System.loadLibrary("shell_elf");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());
    }

    /**
     * A native method that is implemented by the 'shell_elf' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}