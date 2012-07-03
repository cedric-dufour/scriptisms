package ch.skyguide.eVFRManual;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebSettings;
import android.webkit.WebChromeClient;
import android.webkit.WebViewClient;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

public class eVFRManualActivity extends Activity
{
  WebView myWebView;
  WebSettings myWebSettings;

  // Called on activity start or
  // on configuration change (orientation, keyboard, screen size, etc.)
  @Override public void onCreate( Bundle savedInstanceState )
  {
    super.onCreate( savedInstanceState );
    this.setContentView( R.layout.main );
    myWebView = (WebView)findViewById( R.id.eVFRManual );
    myWebSettings = myWebView.getSettings();
    myWebSettings.setCacheMode( WebSettings.LOAD_NO_CACHE );
    myWebSettings.setJavaScriptEnabled( true );
    //myWebSettings.setAllowFileAccessFromFileURLs( true ); // API >= 16
    myWebSettings.setLayoutAlgorithm( WebSettings.LayoutAlgorithm.NORMAL );
    myWebSettings.setBuiltInZoomControls( true );
    myWebSettings.setUseWideViewPort( true );
    myWebView.setWebChromeClient( new WebChromeClient() );
    myWebView.setWebViewClient( new WebViewClient() );
    if( savedInstanceState == null )
    {
      myWebView.loadUrl( "file:///android_asset/index.html" );
    }
    else
    {
      myWebView.restoreState( savedInstanceState );
    }
  }

  // Called before activity is sent to background or
  // before configuration change (orientation, keyboard, screen size, etc.)
  @Override protected void onSaveInstanceState( Bundle outState )
  {
    myWebView.saveState( outState );
    super.onSaveInstanceState( outState );
  }

  // Called when hardware back button is pressed
  @Override public void onBackPressed()
  {
    if( myWebView.canGoBack() ) myWebView.goBack();
    else this.moveTaskToBack( true );
    return;
  }

  // Options menu creation
  @Override public boolean onCreateOptionsMenu( Menu menu )
  {
    this.getMenuInflater().inflate( R.menu.main, menu );
    return true;
  }

  // Options menu handling
  @Override public boolean onOptionsItemSelected( MenuItem item )
  {
    switch( item.getItemId() )
    {
    case R.id.home:
      myWebView.loadUrl( "file:///android_asset/index.html" );
      return true;

    case R.id.version:
      String version = "unknown";
      try { version = this.getPackageManager().getPackageInfo( this.getPackageName(), 0 ).versionName; }
      catch( android.content.pm.PackageManager.NameNotFoundException e ) {}
      Toast.makeText( this, version, Toast.LENGTH_SHORT ).show();
      return true;

    case R.id.exit:
      this.moveTaskToBack( true ); // NOTE: Android guidelines recommends against "killing" activities; so be it!
      return true;

    default:
      return super.onOptionsItemSelected(item);
    }
  }

}
