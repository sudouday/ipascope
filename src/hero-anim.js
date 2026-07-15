// Small particle background for arc reactor
(function(){
  const canvas = document.getElementById('reactor-particles');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let DPR = window.devicePixelRatio || 1;
  function resize(){
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.max(1, Math.floor(rect.width * DPR));
    canvas.height = Math.max(1, Math.floor(rect.height * DPR));
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
    ctx.setTransform(DPR,0,0,DPR,0,0);
  }
  resize();
  window.addEventListener('resize', resize);

  const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
  if(mq.matches) return; // don't animate

  const particles = [];
  function spawn(){
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    particles.push({
      x: w/2 + (Math.random()-0.5)*60,
      y: h/2 + (Math.random()-0.5)*60,
      vx: (Math.random()-0.5)*0.5,
      vy: (Math.random()-0.5)*0.3 - 0.05,
      r: 0.6 + Math.random()*2.4,
      life: 60 + Math.floor(Math.random()*120)
    });
    if(particles.length>80) particles.shift();
  }
  function step(){
    ctx.clearRect(0,0,canvas.width/DPR, canvas.height/DPR);
    for(let i=particles.length-1;i>=0;i--){
      const p = particles[i];
      p.x += p.vx; p.y += p.vy; p.life--;
      if(p.life<=0){ particles.splice(i,1); continue; }
      ctx.beginPath();
      const alpha = Math.max(0, Math.min(1, p.life/120));
      ctx.fillStyle = `rgba(120,200,255,${alpha*0.9})`;
      ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fill();
    }
    if(Math.random() < 0.35) spawn();
    requestAnimationFrame(step);
  }
  step();
})();
