import { ArrowLeft } from "lucide-react";

export function AuthBackButton({ children = "Back to sign in", onClick }) {
  return (
    <button className="back-button" type="button" onClick={onClick}>
      <ArrowLeft size={16} aria-hidden="true" /> {children}
    </button>
  );
}

export function AuthCardIntro({
  icon: Icon,
  iconState = "",
  kicker,
  title,
  titleId,
  children,
}) {
  return (
    <>
      <div className={`card-symbol ${iconState}`} aria-hidden="true">
        <Icon size={22} />
      </div>
      <p className="card-kicker">{kicker}</p>
      <h1 id={titleId}>{title}</h1>
      <div className="card-copy">{children}</div>
    </>
  );
}
