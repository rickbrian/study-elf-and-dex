package com.org.shell_elf;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import com.org.shell_elf.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'shell_elf' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());


        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int n = Add(100, 10);
                int n1 = Sub(100,50);
                Log.d("TAG", "onCreate: " +n );
                Log.d("TAG", "onCreate: " + n1);
            }
        });



    }

    /**
     * A native method that is implemented by the 'shell_elf' native library,
     * which is packaged with this application.
     */

    public  native  int Add(int n,int n1);
    public  native  int Sub(int n,int n1);

    public native int test(int n,int n1);
}

